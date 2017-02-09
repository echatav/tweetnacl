module Crypto.Tweet.C
  ( crypto_box_curve25519xsalsa20poly1305_tweet
  , crypto_box_curve25519xsalsa20poly1305_tweet_open
  , crypto_box_curve25519xsalsa20poly1305_tweet_keypair
  , crypto_box_curve25519xsalsa20poly1305_tweet_beforenm
  , crypto_box_curve25519xsalsa20poly1305_tweet_afternm
  , crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm
  , crypto_core_salsa20_tweet
  , crypto_core_hsalsa20_tweet
  , crypto_hashblocks_sha512_tweet
  , crypto_hash_sha512_tweet
  , crypto_onetimeauth_poly1305_tweet
  , crypto_onetimeauth_poly1305_tweet_verify
  , crypto_scalarmult_curve25519_tweet
  , crypto_scalarmult_curve25519_tweet_base
  , crypto_secretbox_xsalsa20poly1305_tweet
  , crypto_secretbox_xsalsa20poly1305_tweet_open
  , crypto_sign_ed25519_tweet
  , crypto_sign_ed25519_tweet_open
  , crypto_sign_ed25519_tweet_keypair
  , crypto_stream_xsalsa20_tweet
  , crypto_stream_xsalsa20_tweet_xor
  , crypto_stream_salsa20_tweet
  , crypto_stream_salsa20_tweet_xor
  , crypto_verify_16_tweet
  , crypto_verify_32_tweet
  ) where

import Foreign.C
import Foreign.Ptr

foreign import ccall "crypto_box_curve25519xsalsa20poly1305_tweet"
  crypto_box_curve25519xsalsa20poly1305_tweet
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_box_curve25519xsalsa20poly1305_tweet_open"
  crypto_box_curve25519xsalsa20poly1305_tweet_open
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_box_curve25519xsalsa20poly1305_tweet_keypair"
  crypto_box_curve25519xsalsa20poly1305_tweet_keypair
    :: Ptr CUChar
    -> Ptr CUChar
    -> IO CInt

foreign import ccall "crypto_box_curve25519xsalsa20poly1305_tweet_beforenm"
  crypto_box_curve25519xsalsa20poly1305_tweet_beforenm
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_box_curve25519xsalsa20poly1305_tweet_afternm"
  crypto_box_curve25519xsalsa20poly1305_tweet_afternm
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm"
  crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_core_salsa20_tweet"
  crypto_core_salsa20_tweet
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_core_hsalsa20_tweet"
  crypto_core_hsalsa20_tweet
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_hashblocks_sha512_tweet"
  crypto_hashblocks_sha512_tweet
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> IO CInt

foreign import ccall "crypto_hash_sha512_tweet"
  crypto_hash_sha512_tweet
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> IO CInt

foreign import ccall "crypto_onetimeauth_poly1305_tweet"
  crypto_onetimeauth_poly1305_tweet
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_onetimeauth_poly1305_tweet_verify"
  crypto_onetimeauth_poly1305_tweet_verify
    :: Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_scalarmult_curve25519_tweet"
  crypto_scalarmult_curve25519_tweet
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_scalarmult_curve25519_tweet_base"
  crypto_scalarmult_curve25519_tweet_base
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_secretbox_xsalsa20poly1305_tweet"
  crypto_secretbox_xsalsa20poly1305_tweet
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_secretbox_xsalsa20poly1305_tweet_open"
  crypto_secretbox_xsalsa20poly1305_tweet_open
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_sign_ed25519_tweet"
  crypto_sign_ed25519_tweet
    :: Ptr CUChar
    -> Ptr CULLong
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_sign_ed25519_tweet_open"
  crypto_sign_ed25519_tweet_open
    :: Ptr CUChar
    -> Ptr CULLong
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_sign_ed25519_tweet_keypair"
  crypto_sign_ed25519_tweet_keypair
    :: Ptr CUChar
    -> Ptr CUChar
    -> IO CInt

foreign import ccall "crypto_stream_xsalsa20_tweet"
  crypto_stream_xsalsa20_tweet
    :: Ptr CUChar
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_stream_xsalsa20_tweet_xor"
  crypto_stream_xsalsa20_tweet_xor
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_stream_salsa20_tweet"
  crypto_stream_salsa20_tweet
    :: Ptr CUChar
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_stream_salsa20_tweet_xor"
  crypto_stream_salsa20_tweet_xor
    :: Ptr CUChar
    -> Ptr CUChar -- const
    -> CULLong
    -> Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_verify_16_tweet"
  crypto_verify_16_tweet
    :: Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt

foreign import ccall "crypto_verify_32_tweet"
  crypto_verify_32_tweet
    :: Ptr CUChar -- const
    -> Ptr CUChar -- const
    -> IO CInt
