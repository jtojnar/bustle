{-
Bustle.UI.Recorder: dialogs for driving Bustle.Monitor
Copyright © 2012 Collabora Ltd.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
-}
module Bustle.UI.Recorder
  (
    recorderChooseFile
  , recorderRun
  , BusType(..)
  )
where

import Control.Monad (when, liftM)
import Control.Concurrent.MVar
import qualified Data.Map as Map
import Data.Monoid
import Data.Maybe (maybeToList)
import Control.Monad.State (runStateT)
import Text.Printf

import qualified Control.Exception as C
import System.GIO.Enums (IOErrorEnum(IoErrorCancelled))
import System.Glib.GObject (quarkFromString)
import System.Glib.GError
import Graphics.UI.Gtk

import Bustle.Loader.Pcap (convert)
import Bustle.Loader (isRelevant)
import Bustle.Marquee (toString)
import Bustle.Monitor
import Bustle.Renderer
import Bustle.Translation (__)
import Bustle.Types
import Bustle.UI.Util (displayError)
import Bustle.Util

type RecorderIncomingCallback = RendererResult Participants
                             -> IO ()
type RecorderFinishedCallback = Bool -- ^ was anything meaningful actually recorded?
                             -> IO ()

processBatch :: MVar [DetailedEvent]
             -> MVar Int
             -> Label
             -> RecorderIncomingCallback
             -> IO (IO Bool)
processBatch pendingRef n label incoming = do
    rendererStateRef <- newMVar rendererStateNew
    -- FIXME: this is stupid. If we have to manually combine the outputs, it's
    -- basically just more state.
    rendererResultRef <- newMVar mempty

    return $ do
        pending <- takeMVar pendingRef
        putMVar pendingRef []

        when (not (null pending)) $ do
            rr <- modifyMVar rendererStateRef $ \s -> do
                let (rr, s') = processSome (reverse pending) [] s
                return (s', rr)

            oldRR <- takeMVar rendererResultRef
            let rr' = oldRR `mappend` rr
            putMVar rendererResultRef rr'

            when (not (null (rrShapes rr))) $ do
                -- If the renderer produced some visible output, count it as a
                -- message from the user's perspective.
                i <- takeMVar n
                let j = i + (length pending)
                labelSetMarkup label $
                    (printf (__ "Logged <b>%u</b> messages…") j :: String)
                putMVar n j

                incoming rr'

        return True

recorderRun :: BusType
            -> FilePath
            -> Maybe Window
            -> RecorderIncomingCallback
            -> RecorderFinishedCallback
            -> IO ()
recorderRun busType filename mwindow incoming finished = C.handle newFailed $ do
    monitor <- monitorNew busType filename
    dialog <- dialogNew

    dialog `set` (map (windowTransientFor :=) (maybeToList mwindow))
    dialog `set` [ windowModal := True
                 , windowTitle := ""
                 ]


    label <- labelNew (Nothing :: Maybe String)
    labelSetMarkup label $
        (printf (__ "Logged <b>%u</b> messages…") (0 :: Int) :: String)
    loaderStateRef <- newMVar Map.empty
    pendingRef <- newMVar []
    let updateLabel µs body = do
            -- of course, modifyMVar and runStateT have their tuples back to front.
            m <- modifyMVar loaderStateRef $ \s -> do
                (m, s') <- runStateT (convert µs body) s
                return (s', m)

            case m of
                Left e -> warn e
                Right message
                  | isRelevant (deEvent message) -> do
                        modifyMVar_ pendingRef $ \pending -> return (message:pending)
                  | otherwise -> return ()

    handlerId <- monitor `on` monitorMessageLogged $ updateLabel
    errorHandlerId <- monitor `on` monitorError $ \_domain _code message -> do
        dialogResponse dialog ResponseClose
        displayError mwindow (toString message) Nothing

    n <- newMVar (0 :: Int)
    processor <- processBatch pendingRef n label incoming
    processorId <- timeoutAdd processor 200

    spinner <- spinnerNew
    spinnerStart spinner

    vbox <- fmap castToBox $ dialogGetContentArea dialog
    hbox <- hBoxNew False 8
    boxPackStart hbox spinner PackNatural 0
    boxPackStart hbox label PackGrow 0
    boxPackStart vbox hbox PackGrow 0

    dialogAddButton dialog "gtk-media-stop" ResponseClose

    dialog `after` response $ \_ -> do
        monitorStop monitor
        signalDisconnect handlerId
        signalDisconnect errorHandlerId
        spinnerStop spinner
        timeoutRemove processorId
        -- Flush out any last messages from the queue.
        processor
        widgetDestroy dialog
        hadOutput <- liftM (/= 0) (readMVar n)
        finished hadOutput

    widgetShowAll dialog
  where
    -- Filter out IoErrorCancelled. In theory one should use
    --   catchGErrorJust IoErrorCancelled computation (\_ -> return ())
    -- but IOErrorEnum does not have an instance for GError domain.
    newFailed (GError domain code message) = do
        finished False
        gIoErrorQuark <- quarkFromString "g-io-error-quark"
        let cancelled = fromEnum IoErrorCancelled
        if domain == gIoErrorQuark && code == cancelled
            then return ()
            else displayError mwindow (toString message) Nothing

recorderChooseFile :: FilePath
                   -> Maybe Window
                   -> (FilePath -> IO ())
                   -> IO ()
recorderChooseFile name mwindow callback = do
    chooser <- fileChooserDialogNew Nothing mwindow FileChooserActionSave
             [ ("gtk-cancel", ResponseCancel)
             , ("gtk-new", ResponseAccept)
             ]
    fileChooserSetCurrentName chooser name
    chooser `set` [ windowModal := True
                  , fileChooserLocalOnly := True
                  , fileChooserDoOverwriteConfirmation := True
                  ]

    chooser `after` response $ \resp -> do
        when (resp == ResponseAccept) $ do
            Just fn <- fileChooserGetFilename chooser
            callback fn
        widgetDestroy chooser

    widgetShowAll chooser
