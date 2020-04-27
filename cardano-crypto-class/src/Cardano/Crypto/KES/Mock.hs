{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Mock
  ( MockKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  )
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..), decodeListLenOf, encodeListLen)
import Cardano.Crypto.Hash
import Cardano.Crypto.Seed
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Util (nonNegIntR)
import Cardano.Prelude (NoUnexpectedThunks)
import GHC.Generics (Generic)
import GHC.TypeNats (Nat, KnownNat, natVal)
import Data.Proxy (Proxy(..))
import Numeric.Natural (Natural)
import Control.Exception (assert)

data MockKES (t :: Nat)

type H = MD5

-- | Mock key evolving signatures.
--
-- What is the difference between Mock KES and Simple KES
-- (@Cardano.Crypto.KES.Simple@), you may ask? Simple KES satisfies the outward
-- appearance of a KES scheme through assembling a pre-generated list of keys
-- and iterating through them. Mock KES, on the other hand, pretends to be KES
-- but in fact does no key evolution whatsoever.
--
-- Simple KES is appropriate for testing, since it will for example reject old
-- keys. Mock KES is more suitable for a basic testnet, since it doesn't suffer
-- from the performance implications of shuffling a giant list of keys around
instance KnownNat t => KESAlgorithm (MockKES t) where

    type Signable (MockKES t) = ToCBOR

    newtype VerKeyKES (MockKES t) = VerKeyMockKES Int
        deriving stock   (Show, Eq, Ord, Generic)
        deriving newtype (NoUnexpectedThunks, ToCBOR, FromCBOR)

    data SignKeyKES (MockKES t) =
           SignKeyMockKES !(VerKeyKES (MockKES t)) !Natural
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoUnexpectedThunks)

    data SigKES (MockKES t) =
           SigMockKES !Natural !(SignKeyKES (MockKES t))
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoUnexpectedThunks)

    encodeVerKeyKES = toCBOR
    encodeSignKeyKES = toCBOR
    encodeSigKES = toCBOR

    decodeSignKeyKES = fromCBOR
    decodeVerKeyKES = fromCBOR
    decodeSigKES = fromCBOR

    seedSizeKES _ = 4
    genKeyKES seed =
        let vk = VerKeyMockKES (runMonadRandomWithSeed seed nonNegIntR)
         in SignKeyMockKES vk 0

    deriveVerKeyKES (SignKeyMockKES vk _) = vk

    updateKES () (SignKeyMockKES vk k) to =
      assert (to >= k) $
         if to < totalPeriodsKES (Proxy @ (MockKES t))
           then Just (SignKeyMockKES vk to)
           else Nothing

    -- | Produce valid signature only with correct key, i.e., same iteration and
    -- allowed KES period.
    signKES () j a (SignKeyMockKES vk k)
        | j == k
        , j  < totalPeriodsKES (Proxy @ (MockKES t))
        = Just (SigMockKES (fromHash $ hash @H a) (SignKeyMockKES vk j))

        | otherwise
        = Nothing

    verifyKES () vk j a (SigMockKES h (SignKeyMockKES vk' j')) =
        if    j  == j'
           && vk == vk'
           && fromHash (hash @H a) == h
          then Right ()
          else Left "KES verification failed"

    currentPeriodKES () (SignKeyMockKES _ k) = k
    totalPeriodsKES  _ = natVal (Proxy @ t)

instance KnownNat t => ToCBOR (SigKES (MockKES t)) where
  toCBOR (SigMockKES evolution key) =
    encodeListLen 2 <>
      toCBOR evolution <>
      toCBOR key

instance KnownNat t => FromCBOR (SigKES (MockKES t)) where
  fromCBOR =
    SigMockKES <$
      decodeListLenOf 2 <*>
      fromCBOR <*>
      fromCBOR

instance KnownNat t => ToCBOR (SignKeyKES (MockKES t)) where
  toCBOR (SignKeyMockKES vk k) =
    encodeListLen 2 <>
      toCBOR vk <>
      toCBOR k

instance KnownNat t => FromCBOR (SignKeyKES (MockKES t)) where
  fromCBOR =
    SignKeyMockKES <$
      decodeListLenOf 2 <*>
      fromCBOR <*>
      fromCBOR
