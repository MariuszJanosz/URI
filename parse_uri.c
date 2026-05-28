#include "uri.h"

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

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

StringView cstr_to_StringView(const char* cstr) {
    if (!cstr) return (StringView){NULL, 0};
    return (StringView){cstr, strlen(cstr)};
}

UriParsingStatus parse_URI(const char* cstr, URI* res) {
    if (!cstr) return URI_PARSING_FAIL;
    memset(res, 0, sizeof(*res));
    size_t i = 0;
    //find scheme
    while (cstr[i] != ':' && cstr[i] != '\0') ++i;
    if (cstr[i] == '\0') return URI_PARSING_FAIL;
    res->scheme.cstr = cstr;
    res->scheme.len = i;
    ++i;
    //if there is "//" it should have authority
    int has_authority = (cstr[i] == '/' && cstr[i + 1] == '/');
    if (has_authority) {
        i += 2;
        res->host.cstr = cstr + i;
        ssize_t last_at = -1;
        ssize_t last_colon = -1;
        ssize_t closing_sbracket = -1;
        while (cstr[i] != '/' && cstr[i] != '?' && cstr[i] != '#' && cstr[i] != '\0') {
            switch (cstr[i]) {
                case '@':
                    last_at = i;
                    break;
                case ':':
                    last_colon = i;
                    break;
                case ']':
                    closing_sbracket = i;
                    break;
            }
            ++i;
        }
        //determin borders based on found delimeters
        if (last_at != -1) {
            res->userinfo.cstr = res->host.cstr;
            res->userinfo.len = last_at - (res->userinfo.cstr - cstr);
            res->host.cstr = cstr + last_at + 1;
        }
        if (last_colon > closing_sbracket) {
            res->host.len = last_colon - (res->host.cstr - cstr);
            res->port.cstr = cstr + last_colon + 1;
            res->port.len = i - (res->port.cstr - cstr);
        }
        else {
            res->host.len = i - (res->host.cstr - cstr);
        }
    }
    res->path.cstr = cstr + i;
    if (cstr[i] == '?' || cstr[i] == '#' || cstr[i] == '\0') {
        //in this case path was empty
        res->path.len = 0;
    }
    else {
        while (cstr[i] != '?' && cstr[i] != '#' && cstr[i] != '\0') ++i;
        res->path.len = i - (res->path.cstr - cstr);
    }
    if (cstr[i] == '?') {
        //in this case there is query
        ++i;
        res->query.cstr = cstr + i;
        while (cstr[i] != '#' && cstr[i] != '\0') ++i;
        res->query.len = i - (res->query.cstr - cstr);
    }
    if (cstr[i] == '#') {
        //in this case there is fragment
        ++i;
        res->fragment.cstr = cstr + i;
        while (cstr[i] != '\0') ++i;
        res->fragment.len = i - (res->fragment.cstr - cstr);
    }
    if (!uri_is_scheme(res->scheme.cstr, res->scheme.len)) return URI_PARSING_FAIL;
    if (!uri_is_userinfo(res->userinfo.cstr, res->userinfo.len)) return URI_PARSING_FAIL;
    if (!uri_is_host(res->host.cstr, res->host.len)) return URI_PARSING_FAIL;
    if (!uri_is_port(res->port.cstr, res->port.len)) return URI_PARSING_FAIL;
    if (!uri_is_path(res->path.cstr, res->path.len)) return URI_PARSING_FAIL;
    if (!uri_is_query(res->query.cstr, res->query.len)) return URI_PARSING_FAIL;
    if (!uri_is_fragment(res->fragment.cstr, res->fragment.len)) return URI_PARSING_FAIL;
    return URI_PARSING_SUCCESS;
}

void print_StringView(StringView sv) {
    printf("%.*s\n", (int)sv.len, sv.cstr);
}

int main() {
    const char* strings[] =
        {   "http://www.example.com:80/a/b/c/d/index.html?rwf=22#end_end",
            "https:/",
            "file:///home/user/file.txt",
            "https://blah@www.exmple.com:443/ewgrw/bewg/index.html?q=64;rhef#test"
        };
    for (int i = 0; i < sizeof(strings) / sizeof(strings[0]); ++i) {
        const char* cstr = strings[i];
        URI uri;
        if (parse_URI(cstr, &uri) == URI_PARSING_FAIL) exit(1);
        printf("scheme: "); print_StringView(uri.scheme);
        printf("userinfo: "); print_StringView(uri.userinfo);
        printf("host: "); print_StringView(uri.host);
        printf("port: "); print_StringView(uri.port);
        printf("path: "); print_StringView(uri.path);
        printf("query: "); print_StringView(uri.query);
        printf("fragment: "); print_StringView(uri.fragment);
    }
    return 0;
}

