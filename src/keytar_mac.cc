#include <Security/Security.h>
#include "keytar.h"
#include "credentials.h"
#include <iostream>


namespace keytar {

/**
 * Converts a CFString to a std::string
 *
 * This either uses CFStringGetCStringPtr or (if that fails)
 * CFStringGetCString, trying to be as efficient as possible.
 */
const std::string CFStringToStdString(CFStringRef cfstring) {
        const char* cstr = CFStringGetCStringPtr(cfstring, kCFStringEncodingUTF8);

        if (cstr != NULL) {
                return std::string(cstr);
        }

        CFIndex length = CFStringGetLength(cfstring);
        // Worst case: 2 bytes per character + NUL
        CFIndex cstrPtrLen = length * 2 + 1;
        char* cstrPtr = static_cast<char*>(malloc(cstrPtrLen));

        Boolean result = CFStringGetCString(cfstring,
                                            cstrPtr,
                                            cstrPtrLen,
                                            kCFStringEncodingUTF8);

        std::string stdstring;
        if (result) {
                stdstring = std::string(cstrPtr);
        }

        free(cstrPtr);

        return stdstring;
}

const std::string errorStatusToString(OSStatus status) {
        std::string errorStr;
        CFStringRef errorMessageString = SecCopyErrorMessageString(status, NULL);

        const char* errorCStringPtr = CFStringGetCStringPtr(errorMessageString,
                                                            kCFStringEncodingUTF8);
        if (errorCStringPtr) {
                errorStr = std::string(errorCStringPtr);
        } else {
                errorStr = std::string("An unknown error occurred.");
        }

        CFRelease(errorMessageString);
        return errorStr;
}

KEYTAR_OP_RESULT AddPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* error,
                             bool returnNonfatalOnDuplicate) {
        OSStatus status = SecKeychainAddInternetPassword(NULL,
                                                         service.length(),
                                                         service.data(),
                                                         0,
                                                         NULL,
                                                         account.length(),
                                                         account.data(),
                                                         0,
                                                         NULL,
                                                         0,
                                                         kSecProtocolTypeAny,
                                                         kSecAuthenticationTypeDefault,
                                                         password.length(),
                                                         password.data(),
                                                         NULL);

        if (status == errSecDuplicateItem && returnNonfatalOnDuplicate) {
                return FAIL_NONFATAL;
        } else if (status != errSecSuccess) {
                *error = errorStatusToString(status);
                return FAIL_ERROR;
        }

        return SUCCESS;
}

KEYTAR_OP_RESULT SetPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* error) {
        KEYTAR_OP_RESULT result = AddPassword(service, account, password,
                                              error, true);
        if (result == FAIL_NONFATAL) {
                // This password already exists, delete it and try again.
                KEYTAR_OP_RESULT delResult = DeletePassword(service, account, error);
                if (delResult == FAIL_ERROR)
                        return FAIL_ERROR;
                else
                        return AddPassword(service, account, password, error, false);
        } else if (result == FAIL_ERROR) {
                return FAIL_ERROR;
        }

        return SUCCESS;
}

KEYTAR_OP_RESULT GetPassword(const std::string& service,
                             const std::string& account,
                             std::string* password,
                             std::string* error) {
        void *data;
        UInt32 length;
        OSStatus status = SecKeychainFindInternetPassword(NULL,
                                                          service.length(),
                                                          service.data(),
                                                          0,
                                                          NULL,
                                                          account.length(),
                                                          account.data(),
                                                          0,
                                                          NULL,
                                                          0,
                                                          kSecProtocolTypeAny,
                                                          kSecAuthenticationTypeAny,
                                                          &length,
                                                          &data,
                                                          NULL);

        if (status == errSecItemNotFound) {
                return FAIL_NONFATAL;
        } else if (status != errSecSuccess) {
                *error = errorStatusToString(status);
                return FAIL_ERROR;
        }

        *password = std::string(reinterpret_cast<const char*>(data), length);
        SecKeychainItemFreeContent(NULL, data);
        return SUCCESS;
}

KEYTAR_OP_RESULT DeletePassword(const std::string& service,
                                const std::string& account,
                                std::string* error) {
        SecKeychainItemRef item;
        OSStatus status = SecKeychainFindInternetPassword(NULL,
                                                          service.length(),
                                                          service.data(),
                                                          0,
                                                          NULL,
                                                          account.length(),
                                                          account.data(),
                                                          0,
                                                          NULL,
                                                          0,
                                                          kSecProtocolTypeAny,
                                                          kSecAuthenticationTypeAny,
                                                          NULL,
                                                          NULL,
                                                          &item);
        if (status == errSecItemNotFound) {
                // Item could not be found, so already deleted.
                return FAIL_NONFATAL;
        } else if (status != errSecSuccess) {
                *error = errorStatusToString(status);
                return FAIL_ERROR;
        }

        status = SecKeychainItemDelete(item);
        CFRelease(item);
        if (status != errSecSuccess) {
                *error = errorStatusToString(status);
                return FAIL_ERROR;
        }

        return SUCCESS;
}

KEYTAR_OP_RESULT FindPassword(const std::string& service,
                              std::string* password,
                              std::string* error) {
        SecKeychainItemRef item;
        void *data;
        UInt32 length;

        OSStatus status = SecKeychainFindInternetPassword(NULL,
                                                          service.length(),
                                                          service.data(),
                                                          0,
                                                          NULL,
                                                          0,
                                                          NULL,
                                                          0,
                                                          NULL,
                                                          0,
                                                          kSecProtocolTypeAny,
                                                          kSecAuthenticationTypeAny,
                                                          &length,
                                                          &data,
                                                          &item);
        if (status == errSecItemNotFound) {
                return FAIL_NONFATAL;
        } else if (status != errSecSuccess) {
                *error = errorStatusToString(status);
                return FAIL_ERROR;
        }

        *password = std::string(reinterpret_cast<const char*>(data), length);
        SecKeychainItemFreeContent(NULL, data);
        CFRelease(item);
        return SUCCESS;
}

KEYTAR_OP_RESULT FindCredentials(const std::string& service,
                                 std::vector<Credentials>* credentials,
                                 std::string* error) {
        CFStringRef serviceStr = CFStringCreateWithCString(
                NULL,
                service.c_str(),
                kCFStringEncodingUTF8);

        CFMutableDictionaryRef query = CFDictionaryCreateMutable(
                NULL,
                0,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(query, kSecClass, kSecClassInternetPassword);
        CFDictionaryAddValue(query, kSecAttrServer, serviceStr);
        CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);
        CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
        CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);

        CFTypeRef result;
        OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &result);

        if (status == errSecSuccess) {

                CFArrayRef resultArray = (CFArrayRef) result;
                int resultCount = CFArrayGetCount(resultArray);
                for (int idx = 0; idx < resultCount; idx++) {
                        CFDictionaryRef item = (CFDictionaryRef) CFArrayGetValueAtIndex(
                                resultArray,
                                idx);

                        CFStringRef service = (CFStringRef) CFDictionaryGetValue(item, kSecAttrServer);
                        CFStringRef account = (CFStringRef) CFDictionaryGetValue(item, kSecAttrAccount);
                        std::vector<std::pair< std::string, const std::string > > settings;
                        CFStringRef path = (CFStringRef) CFDictionaryGetValue(item, kSecAttrPath);
                        if(path != nullptr) {
                                std::string _path = CFStringToStdString(path);
                                std::pair<std::string, std::string> pathPair = std::make_pair("path", _path);
                                settings.push_back(pathPair);
                        }
                        CFTypeRef domain = nil;
                        CFDictionaryGetValueIfPresent(item, kSecAttrSecurityDomain, &domain);
                        if(domain) {
                                settings.push_back(std::make_pair<std::string, const std::string >("domain", CFStringToStdString((CFStringRef)domain)));
                        }
                        CFTypeRef port = nil;
                        CFDictionaryGetValueIfPresent(item, kSecAttrPort, &port);
                        if(port) {
                                int _port;
                                CFNumberGetValue((CFNumberRef) port, kCFNumberIntType, &_port);
                                settings.push_back(std::make_pair<std::string, const std::string >("port", std::to_string(_port)));
                        }
                        CFTypeRef protocol = nil;
                        CFDictionaryGetValueIfPresent(item, kSecAttrProtocol, &protocol);
                        if(protocol) {
                                settings.push_back(std::make_pair<std::string, const std::string >("protocol", CFStringToStdString((CFStringRef) protocol)));
                        }
                        Credentials cred = Credentials(
                                CFStringToStdString(service),
                                CFStringToStdString(account),
                                settings
                                );
                        credentials->push_back(cred);
                }
        } else if (status == errSecItemNotFound) {
                return FAIL_NONFATAL;
        } else {
                *error = errorStatusToString(status);
                return FAIL_ERROR;
        }


        if (result != NULL) {
                CFRelease(result);
        }

        CFRelease(query);

        return SUCCESS;
}

}  // namespace keytar
