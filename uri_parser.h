#ifndef URI_PARSER_H
#define URI_PARSER_H

#include <stddef.h>

typedef struct StringView {
    const char* cstr;
    size_t len;
} StringView;

typedef struct URI {
    StringView scheme;
    StringView userinfo;
    StringView host;
    StringView port;
    StringView path;
    StringView query;
    StringView fragment;
} URI;

typedef enum UriParsingStatus {
    URI_PARSING_SUCCESS,
    URI_PARSING_FAIL
} UriParsingStatus;

UriParsingStatus parse_URI(const char* cstr, URI* res);
UriParsingStatus parse_relative_ref(const char* cstr, URI* res);

#endif //URI_PARSER_H

