#pragma once

#include <stdexcept>

namespace aes {

class Error : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};
class RandomError : public Error {
   public:
    using Error::Error;
};
class KeyError : public Error {
   public:
    using Error::Error;
};
class FormatError : public Error {
   public:
    using Error::Error;
};
class IoError : public Error {
   public:
    using Error::Error;
};
class CryptoError : public Error {
   public:
    using Error::Error;
};
}  // namespace aes
