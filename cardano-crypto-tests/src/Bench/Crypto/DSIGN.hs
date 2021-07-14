{-#LANGUAGE DataKinds #-}
{-#LANGUAGE TypeApplications #-}
{-#LANGUAGE ScopedTypeVariables #-}
{-#LANGUAGE NoImplicitPrelude #-}
{-#LANGUAGE TypeFamilies #-}
{-#LANGUAGE FlexibleContexts #-}
{-#LANGUAGE OverloadedStrings #-}
module Bench.Crypto.DSIGN
  ( benchmarks
  ) where

import Prelude
import Data.Proxy
import Data.ByteString (ByteString)

import Control.DeepSeq

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.DSIGN.Ed25519
import Cardano.Crypto.Libsodium.DSIGN
import Cardano.Crypto.Libsodium.MLockedBytes

import Criterion

import Bench.Crypto.BenchData

{- HLINT ignore "Use camelCase" -}


benchmarks :: Benchmark
benchmarks = bgroup "DSIGN"
  [ bench_dsign (Proxy :: Proxy Ed25519DSIGN) "Ed25519"
  , bench_dsign_nacl (Proxy :: Proxy Ed25519DSIGN) "Ed25519/libsodium"
  ]

bench_dsign :: forall v
           . ( DSIGNAlgorithm v
             , ContextDSIGN v ~ ()
             , Signable v ByteString
             , NFData (SignKeyDSIGN v)
             , NFData (VerKeyDSIGN v)
             , NFData (SigDSIGN v)
             )
          => Proxy v
          -> String
          -> Benchmark
bench_dsign _ lbl =
  bgroup lbl
    [ bench "genKeyDSIGN" $
        nf (genKeyDSIGN @v) testSeed


    , env (return (genKeyDSIGN @v testSeed)) $ \signKey ->
      bench "signDSIGN" $
        nf (signDSIGN @v () typicalMsg) signKey


    , env (let signKey = genKeyDSIGN @v testSeed
               verKey  = deriveVerKeyDSIGN signKey
               sig     = signDSIGN @v () typicalMsg signKey
            in return (verKey, sig)
          ) $ \ ~(verKey, sig) ->
      bench "verifyDSIGN" $
        nf (verifyDSIGN @v () verKey typicalMsg) sig
    ]


bench_dsign_nacl :: forall v.
                    SodiumDSIGNAlgorithm v
                 => Proxy v
                 -> String
                 -> Benchmark
bench_dsign_nacl p lbl =
  bgroup lbl
    [ env (return (mlsbFromByteString testBytes)) $ \mlockedBytes ->
      bench "naclGenKeyDSIGN" $
        nf (naclGenKeyDSIGN p) mlockedBytes


    , env (let mlockedBytes = mlsbFromByteString testBytes
               signKey      = naclGenKeyDSIGN p mlockedBytes
            in return signKey) $ \signKey ->
      bench "naclSignDSIGN" $
        nf (naclSignDSIGN p typicalMsg) signKey


    , env (let mlockedBytes = mlsbFromByteString testBytes
               signKey      = naclGenKeyDSIGN p mlockedBytes
               verKey       = naclDeriveVerKeyDSIGN p signKey
               sig          = naclSignDSIGN p typicalMsg signKey
            in return (verKey, sig)
          ) $ \ ~(verKey, sig) ->
      bench "naclVerifyDSIGN" $
        nf (naclVerifyDSIGN p verKey typicalMsg) sig
    ]

