#ifndef SRC_CREDENTIALS_H_
#define SRC_CREDENTIALS_H_

#include <string>
#include <utility>

namespace keytar {

typedef std::tuple<std::string, std::string, std::vector<std::pair<std::string, const std::string >>> Credentials;

}

#endif  // SRC_CREDENTIALS_H_
