/*
 * pcap-monitor.c - monitors a bus and dumps messages to a pcap file
 * Copyright ©2011–2012 Collabora Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"
#include "pcap-monitor.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <pcap/pcap.h>
#include <gio/gunixinputstream.h>

#ifndef DLT_DBUS
# define DLT_DBUS 231
#endif


struct _BustlePcapMonitorPrivate {
    GBusType bus_type;
    gboolean running;
    GCancellable *cancellable;

    /* input */
    GSubprocess *dbus_monitor;
    GSource *dbus_monitor_source;
    pcap_t *pcap_in;

    /* output */
    gchar *filename;
    pcap_t *pcap_out;
    pcap_dumper_t *dumper;
};

enum {
    PROP_BUS_TYPE = 1,
    PROP_FILENAME,
};

enum {
    SIG_MESSAGE_LOGGED,
    SIG_ERROR,
    N_SIGNALS
};

static guint signals[N_SIGNALS];

static void initable_iface_init (
    gpointer g_class,
    gpointer unused);

G_DEFINE_TYPE_WITH_CODE (BustlePcapMonitor, bustle_pcap_monitor, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, initable_iface_init);
    )

static void
bustle_pcap_monitor_init (BustlePcapMonitor *self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, BUSTLE_TYPE_PCAP_MONITOR,
      BustlePcapMonitorPrivate);
  self->priv->bus_type = G_BUS_TYPE_SESSION;
  self->priv->running = FALSE;
  self->priv->cancellable = g_cancellable_new ();
}

static void
bustle_pcap_monitor_get_property (
    GObject *object,
    guint property_id,
    GValue *value,
    GParamSpec *pspec)
{
  BustlePcapMonitor *self = BUSTLE_PCAP_MONITOR (object);
  BustlePcapMonitorPrivate *priv = self->priv;

  switch (property_id)
    {
      case PROP_BUS_TYPE:
        g_value_set_enum (value, priv->bus_type);
        break;
      case PROP_FILENAME:
        g_value_set_string (value, priv->filename);
        break;
      default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

static void
bustle_pcap_monitor_set_property (
    GObject *object,
    guint property_id,
    const GValue *value,
    GParamSpec *pspec)
{
  BustlePcapMonitor *self = BUSTLE_PCAP_MONITOR (object);
  BustlePcapMonitorPrivate *priv = self->priv;

  switch (property_id)
    {
      case PROP_BUS_TYPE:
        priv->bus_type = g_value_get_enum (value);
        break;
      case PROP_FILENAME:
        priv->filename = g_value_dup_string (value);
        break;
      default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

static void
bustle_pcap_monitor_dispose (GObject *object)
{
  BustlePcapMonitor *self = BUSTLE_PCAP_MONITOR (object);
  GObjectClass *parent_class = bustle_pcap_monitor_parent_class;

  /* Make sure we're all closed up. */
  bustle_pcap_monitor_stop (self);
  g_clear_object (&self->priv->cancellable);

  if (parent_class->dispose != NULL)
    parent_class->dispose (object);
}

static void
bustle_pcap_monitor_finalize (GObject *object)
{
  BustlePcapMonitor *self = BUSTLE_PCAP_MONITOR (object);
  BustlePcapMonitorPrivate *priv = self->priv;
  GObjectClass *parent_class = bustle_pcap_monitor_parent_class;

  g_clear_pointer (&priv->filename, g_free);

  if (parent_class->finalize != NULL)
    parent_class->finalize (object);
}

static void
bustle_pcap_monitor_class_init (BustlePcapMonitorClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  GParamSpec *param_spec;

  object_class->get_property = bustle_pcap_monitor_get_property;
  object_class->set_property = bustle_pcap_monitor_set_property;
  object_class->dispose = bustle_pcap_monitor_dispose;
  object_class->finalize = bustle_pcap_monitor_finalize;

  g_type_class_add_private (klass, sizeof (BustlePcapMonitorPrivate));

#define THRICE(x) x, x, x

  param_spec = g_param_spec_enum (THRICE ("bus-type"),
      G_TYPE_BUS_TYPE, G_BUS_TYPE_SESSION,
      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_BUS_TYPE, param_spec);

  param_spec = g_param_spec_string (THRICE ("filename"), NULL,
      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_FILENAME, param_spec);

  /**
   * BustlePcapMonitor::message-logged:
   * @self: the monitor.
   * @sec: seconds since 1970.
   * @usec: microseconds! (These are not combined into a single %gint64 because
   *  my version of gtk2hs crashes when it encounters %G_TYPE_UINT64 in a
   *  #GValue.)
   * @blob: an array of bytes containing the serialized message.
   * @length: the size in bytes of @blob.
   */
  signals[SIG_MESSAGE_LOGGED] = g_signal_new ("message-logged",
      BUSTLE_TYPE_PCAP_MONITOR, G_SIGNAL_RUN_FIRST,
      0, NULL, NULL,
      NULL, G_TYPE_NONE, 4,
      G_TYPE_LONG,
      G_TYPE_LONG,
      G_TYPE_POINTER,
      G_TYPE_UINT);

  /**
   * BustlePcapMonitor::error:
   * @self: the monitor
   * @domain: domain of a #GError (as G_TYPE_UINT because there is no
   *          G_TYPE_UINT32)
   * @code: code of a #GError
   * @message: message of a #GError
   */
  signals[SIG_ERROR] = g_signal_new ("error",
      BUSTLE_TYPE_PCAP_MONITOR, G_SIGNAL_RUN_FIRST,
      0, NULL, NULL,
      NULL, G_TYPE_NONE, 3,
      G_TYPE_UINT,
      G_TYPE_INT,
      G_TYPE_STRING);
}

static void
handle_error (
    BustlePcapMonitor *self,
    const GError *error)
{
  BustlePcapMonitorPrivate *priv = self->priv;

  if (priv->running)
    g_signal_emit (self, signals[SIG_ERROR], 0,
        (guint) error->domain, error->code, error->message);

  bustle_pcap_monitor_stop (self);
}

static gboolean
read_one (
    BustlePcapMonitor *self,
    GError **error)
{
  BustlePcapMonitorPrivate *priv = self->priv;
  struct pcap_pkthdr *hdr;
  const guchar *blob;
  int ret;

  ret = pcap_next_ex (priv->pcap_in, &hdr, &blob);
  switch (ret)
    {
      case 1:
        g_signal_emit (self, signals[SIG_MESSAGE_LOGGED], 0,
            hdr->ts.tv_sec, hdr->ts.tv_usec, blob, hdr->caplen);

        /* cast necessary because pcap_dump has a type matching the callback
         * argument to pcap_loop()
         * TODO don't block
         */
        pcap_dump ((u_char *) priv->dumper, hdr, blob);
        return TRUE;

      case -2:
        /* EOF; shouldn't happen since we waited for the FD to be readable */
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED,
            "EOF when reading from dbus-monitor");
        return FALSE;

      default:
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
            "Error %i reading dbus-monitor stream: %s",
            ret, pcap_geterr (priv->pcap_in));
        return FALSE;
    }
}

static gboolean
dbus_monitor_readable (
    GObject *pollable_input_stream,
    gpointer user_data)
{
  BustlePcapMonitor *self = BUSTLE_PCAP_MONITOR (user_data);
  BustlePcapMonitorPrivate *priv = self->priv;
  g_autoptr(GError) error = NULL;

  if (g_cancellable_set_error_if_cancelled (priv->cancellable, &error) ||
      !read_one (self, &error))
    handle_error (self, error);

  return TRUE;
}

static void
wait_check_cb (
    GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  BustlePcapMonitor *self = BUSTLE_PCAP_MONITOR (user_data);
  BustlePcapMonitorPrivate *priv = self->priv;
  GSubprocess *dbus_monitor = G_SUBPROCESS (source);
  g_autoptr(GError) error = NULL;

  if (!g_cancellable_set_error_if_cancelled (priv->cancellable, &error))
    {
      if (g_subprocess_wait_check_finish (dbus_monitor, result, &error))
        /* Unexpected clean exit */
        g_set_error (&error, G_IO_ERROR, G_IO_ERROR_FAILED,
            "dbus-monitor exited");
      else
        g_prefix_error (&error, "dbus-monitor died: ");
    }

  handle_error (self, error);
  g_clear_object (&self);
}

static gboolean
initable_init (
    GInitable *initable,
    GCancellable *cancellable,
    GError **error)
{
  BustlePcapMonitor *self = BUSTLE_PCAP_MONITOR (initable);
  BustlePcapMonitorPrivate *priv = self->priv;
  const gchar *dbus_monitor_argv_session[] = {
      "dbus-monitor", "--pcap", "--session", NULL
  };
  const gchar *dbus_monitor_argv_system[] = {
      "pkexec", "dbus-monitor", "--pcap", "--system", NULL
  };
  /* TODO: if inside Flatpak, call HostCommand() instead. */
  const gchar * const *dbus_monitor_argv = NULL;
  FILE *dbus_monitor_filep = NULL;
  GInputStream *stdout_pipe = NULL;
  gint stdout_fd = -1;
  char errbuf[PCAP_ERRBUF_SIZE] = {0};

  switch (priv->bus_type)
    {
      case G_BUS_TYPE_SESSION:
        dbus_monitor_argv = dbus_monitor_argv_session;
        break;
      case G_BUS_TYPE_SYSTEM:
        dbus_monitor_argv = dbus_monitor_argv_system;
        break;
      default:
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
            "Can only log the session or system bus");
        return FALSE;
    }

  if (priv->filename == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
          "You must specify a filename");
      return FALSE;
    }

  priv->pcap_out = pcap_open_dead (DLT_DBUS, 1 << 27);
  if (priv->pcap_out == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
          "pcap_open_dead failed. wtf");
      return FALSE;
    }

  priv->dumper = pcap_dump_open (priv->pcap_out, priv->filename);
  if (priv->dumper == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
          "Couldn't open target file %s", pcap_geterr (priv->pcap_out));
      return FALSE;
    }

  priv->dbus_monitor = g_subprocess_newv (
      dbus_monitor_argv, G_SUBPROCESS_FLAGS_STDOUT_PIPE, error);
  if (priv->dbus_monitor == NULL)
    {
      return FALSE;
    }

  stdout_pipe = g_subprocess_get_stdout_pipe (priv->dbus_monitor);
  g_return_val_if_fail (stdout_pipe != NULL, FALSE);
  g_return_val_if_fail (G_IS_POLLABLE_INPUT_STREAM (stdout_pipe), FALSE);
  g_return_val_if_fail (G_IS_UNIX_INPUT_STREAM (stdout_pipe), FALSE);

  stdout_fd = g_unix_input_stream_get_fd (G_UNIX_INPUT_STREAM (stdout_pipe));
  g_return_val_if_fail (stdout_fd >= 0, FALSE);

  dbus_monitor_filep = fdopen(stdout_fd, "r");
  if (dbus_monitor_filep == NULL)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno), "fdopen");
      return FALSE;
    }
  /* fd is owned by the FILE * now */
  g_unix_input_stream_set_close_fd (G_UNIX_INPUT_STREAM (stdout_pipe), FALSE);

  /* Reads the header, synchronously(!), from dbus-monitor, so if pkexec
   * failed, we'll learn here.
   */
  priv->pcap_in = pcap_fopen_offline (dbus_monitor_filep, errbuf);
  if (priv->pcap_in == NULL)
    {
      GError *error2 = NULL;

      /* Cause dbus-monitor to exit, if it hasn't already. */
      fclose (dbus_monitor_filep);

      if (g_subprocess_wait_check (priv->dbus_monitor, NULL, &error2))
        {
          /* dbus-monitor terminated cleanly. Weird. */
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
              "Couldn't read messages from dbus-monitor: %s",
              errbuf);
        }
      else
        {
          /* Check pkexec errors */
          if (priv->bus_type == G_BUS_TYPE_SYSTEM)
            {
              if (g_error_matches (error2, G_SPAWN_EXIT_ERROR, 126))
                {
                  /* dialog dismissed */
                  g_set_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                      "User dismissed polkit authorization dialog");
                  g_clear_error (&error2);
                  return FALSE;
                }

              if (g_error_matches (error2, G_SPAWN_EXIT_ERROR, 127))
                {
                  /* not authorized, authorization couldn't be obtained through
                   * authentication, or an error occurred */
                  g_set_error (error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                      "Not authorized to monitor system bus");
                  g_clear_error (&error2);
                  return FALSE;
                }
            }

          g_propagate_prefixed_error (error, error2,
              "Couldn't launch dbus-monitor: ");
          error2 = NULL;
        }

      return FALSE;
    }
  else
    {
      /* pcap_close() will call fclose() on the FILE * passed to
       * pcap_fopen_offline() */
      dbus_monitor_filep = NULL;
    }

  priv->dbus_monitor_source = g_pollable_input_stream_create_source (
      G_POLLABLE_INPUT_STREAM (stdout_pipe), priv->cancellable);
  g_source_set_callback (priv->dbus_monitor_source,
      (GSourceFunc) dbus_monitor_readable, self, NULL);
  g_source_attach (priv->dbus_monitor_source, NULL);

  g_subprocess_wait_check_async (
      priv->dbus_monitor,
      NULL, /* https://bugzilla.gnome.org/show_bug.cgi?id=786456 */
      wait_check_cb, g_object_ref (self));

  priv->running = TRUE;
  return TRUE;
}

/* FIXME: instead of GInitable + syncronous stop, have
 * bustle_pcap_monitor_record_{async,finish} */
void
bustle_pcap_monitor_stop (
    BustlePcapMonitor *self)
{
  BustlePcapMonitorPrivate *priv = self->priv;

  priv->running = FALSE;

  if (priv->cancellable != NULL)
    g_cancellable_cancel (priv->cancellable);

  g_clear_pointer (&priv->dbus_monitor_source, g_source_destroy);

  /* Closes the stream; should cause dbus-monitor to quit in due course */
  g_clear_pointer (&priv->pcap_in, pcap_close);

  if (priv->dbus_monitor != NULL)
    {
      g_subprocess_send_signal (priv->dbus_monitor, SIGINT);
      /* Don't wait. */
      g_clear_object (&priv->dbus_monitor);
    }

  g_clear_pointer (&priv->dumper, pcap_dump_close);
  g_clear_pointer (&priv->pcap_out, pcap_close);
}

static void
initable_iface_init (
    gpointer g_class,
    gpointer unused)
{
  GInitableIface *iface = g_class;

  iface->init = initable_init;
}

BustlePcapMonitor *
bustle_pcap_monitor_new (
    GBusType bus_type,
    const gchar *filename,
    GError **error)
{
  return g_initable_new (
      BUSTLE_TYPE_PCAP_MONITOR, NULL, error,
      "bus-type", bus_type,
      "filename", filename,
      NULL);
}
