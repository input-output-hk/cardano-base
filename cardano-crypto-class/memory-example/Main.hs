{-# LANGUAGE CPP #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- deprecations disabled to allow using traceMLockedForeignPtr
{-# OPTIONS_GHC -Wno-deprecations #-}
module Main (main) where

import           Data.Proxy (Proxy (..))
import           Foreign.Storable (Storable (poke))
import           Control.Monad (void, when)
import           GHC.Fingerprint (Fingerprint (..))
import           System.Environment (getArgs)

#ifdef MIN_VERSION_unix
import           System.Posix.Process (getProcessID)
#endif

import qualified Data.ByteString as BS

import           Cardano.Crypto.Libsodium
import           Cardano.Crypto.Libsodium.MLockedBytes.Internal (MLockedFiniteBytes (..))
import           Cardano.Crypto.Hash (SHA256, Blake2b_256, digest)

main :: IO ()
main = do
#ifdef MIN_VERSION_unix
    pid <- getProcessID

    putStrLn $ "If you run this test with 'pause' argument"
    putStrLn $ "you may look at /proc/" ++ show pid ++ "/maps"
    putStrLn $ "                /proc/" ++ show pid ++ "/smaps"
#endif

    sodiumInit

    args <- getArgs

    sodiumInit
    example args allocMLockedForeignPtr

    -- example SHA256 hash
    do
      let input = BS.pack [0..255]
      MLFB hash <- digestMLockedBS (Proxy @SHA256) input
      traceMLockedForeignPtr hash
      print (digest (Proxy @SHA256) input)

    -- example Blake2b_256 hash
    do
      let input = BS.pack [0..255]
      MLFB hash <- digestMLockedBS (Proxy @Blake2b_256) input
      traceMLockedForeignPtr hash
      print (digest (Proxy @Blake2b_256) input)

example
    :: [String]
    -> (IO (MLockedForeignPtr Fingerprint))
    -> IO ()
example args alloc = do
    -- create foreign ptr to mlocked memory
    fptr <- alloc
    withMLockedForeignPtr fptr $ \ptr -> poke ptr (Fingerprint 0xdead 0xc0de)

    when ("pause" `elem` args) $ do
        putStrLn "Allocated..."
        void getLine

    -- we shouldn't do this, but rather do computation inside
    -- withForeignPtr on provided Ptr a
    traceMLockedForeignPtr fptr

    MLFB hash <- withMLockedForeignPtr fptr $ \ptr ->
        digestMLockedStorable (Proxy @SHA256) ptr
    -- compare with
    -- Crypto.Hash.SHA256> hash "\x00\x00\x00\x00\x00\x00\xde\xad\x00\x00\x00\x00\x00\x00\xc0\xd
    -- (cryptohash-sha256)
    -- TODO: write proper tests.
    traceMLockedForeignPtr hash

    -- force finalizers
    finalizeMLockedForeignPtr fptr

    when ("pause" `elem` args) $ do
        putStrLn "Finalized..."
        void getLine

    when ("use-after-free" `elem` args) $ do
        -- in this demo we can try to print it again.
        -- this should deterministically cause segmentation fault
        traceMLockedForeignPtr fptr
