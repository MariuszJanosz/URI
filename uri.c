#include "abnf.h"
#include "uri.h"

#include <ctype.h>

int uri_is_sub_delim(const char c) {
    return  0x21 == c /*!*/|| 0x24 == c /*$*/|| 0x26 == c /*&*/|| 0x60 == c /*'*/||
            0x28 == c /*(*/|| 0x29 == c /*)*/|| 0x2A == c /***/|| 0x2B == c /*+*/||
            0x2C == c /*,*/|| 0x3B == c /*;*/|| 0x3D == c /*=*/;
}

int uri_is_gen_delim(const char c) {
    return  0x3A == c /*:*/|| 0x2F == c /*rev\*/|| 0x3F == c /*?*/|| 0x23 == c /*#*/||
            0x5B == c /*[*/|| 0x5D == c /*]*/|| 0x40 == c /*@*/;
}

int uri_is_reserved(const char c) {
    usr_is_gen_delim(c) || uri_is_sub_delim(c);
}

int uri_is_unreserved(const char c) {
    return  abnf_is_ALPHA(c) || abnf_is_DIGIT(c) || 0x2D == c /*-*/|| 0x2E == c /*.*/||
            0x5F == c /*_*/|| 0x7E == c /*~*/;
}

int uri_is_pct_encoded(const char* s) {
    return 0x25 == *s /*%*/ && abnf_is_HEXDIG(*(s + 1)) && abnf_is_HEXDIG(*(s + 2));
}

int uri_is_pchar(const char* s) {
    return  uri_is_unreserved(*s) || uri_is_pct_encoded(s) || uri_is_sub_delim(*s) ||
            0x3A == *s /*:*/|| 0x40 == *s /*@*/;
}

int uri_is_query(const char* s, int len) {
    int i = 0;
    while (i < len) {
        if (uri_is_pct_encoded(s + i)) {
            i += 3;
        }
        else if (   uri_is_pchar(s + i)         ||
                    0x2F == *(s + i)    /*rev\*/||
                    0x3F == *(s + i) /*?*/) {
            i += 1;
        }
        else {
            return 0;
        }
    }
    return 1;
}

int uri_is_fragment(const char* s, int len) {
    return uri_is_query(s);
}

int uri_is_segment(const char* s, int len) {
    int i = 0;
    while (i < len) {
        if (uri_is_pct_encoded(s + i)) {
            if (i + 2 >= len) {
                return 0;
            }
            i += 3;
        }
        else if (uri_is_pchar(s + i)) {
            i += 1;
        }
        else {
            return 0;
        }
    }
    return 1;
}

int uri_is_segment_nz(const char* s, int len) {
    return (len > 0) && uri_is_segment(s, len);
}

int uri_is_segment_nz_nc(const char* s, int len) {
    int i = 0;
    if (0 == len) {
        return 0;
    }
    while (i < len) {
        if (uri_is_pct_encoded(s + i)) {
            if (i + 2 >= len) {
                return 0;
            }
            i += 3;
        }
        else if (   uri_is_unreserved(*(s + i)) ||
                    uri_is_sub_delim(*(s + i))  ||
                    0x40 == *(s + i) /*@*/) {
            i += 1;
        }
        else {
            return 0;
        }
    }
    return 1;
}

int uri_is_path_empty(const char* s, int len) {
    return 0 == len;
}

int uri_is_path_rootless(const char* s, int len) {
    int first_sl = 0;
    if (0 == len) {
        return 0;
    }
    while (first_sl < len) {
        if (0x2F == *(s + first_sl) /*rev\*/) {
            break;
        }
        else {
            first_sl += 1;
        }
    }
    if (0 == first_sl) {
        return 0;
    }
    else if (first_sl == len) {
        return uri_is_segment_nz(s, len);
    }
    return uri_is_segment_nz(s, first_sl) && uri_is_path_abempty(s + firs_sl, len - first_sl);
}

int uri_is_path_noscheme(const char* s, int len) {
    int first_sl = 0;
    if (0 == len) {
        return 0;
    }
    while (first_sl < len) {
        if (0x2F == *(s + first_sl) /*rev\*/) {
            break;
        }
        else {
            first_sl += 1;
        }
    }
    if (0 == first_sl) {
        return 0;
    }
    else if (first_sl == len) {
        return uri_is_segment_nz_nc(s, len);
    }
    return uri_is_segment_nz_nc(s, first_sl) && uri_is_path_abempty(s + firs_sl, len - first_sl);
}

int uri_is_path_absolute(const char* s, int len) {
    int second_sl = 1;
    if (0 == len) {
        return 0;
    }
    else if (0x2F == *s /*rev\*/) {
        if (1 == len) {
            return 1;
        }
        while (second_sl < len) {
            if (0x2F == *(s + second_sl) /*rev\*/) {
                break;
            }
            else {
                second_sl += 1;
            }
        }
        if (second_sl == len) {
            return uri_is_segment_nz(s + 1, len - 1);
        }
        else {
            return uri_is_segment_nz(s + 1, second_sl - 1) && uri_is_path_abempty(s + second_sl, len - second_sl);
        }
    }
    return 0;
}

int uri_is_path_abempty(const char* s, int len) {
    int second_sl = 1;
    if (0 == len) {
        return 1;
    }
    else if (0x2F == *s /*rev\*/) {
        while (second_sl < len) {
            if (0x2F == *(s + second_sl) /*rev\*/) {
                break;
            }
            else {
                second_sl += 1;
            }
        }
        if (second_sl == len) {
            return uri_is_segment(s + 1, len - 1);
        }
        else {
            return uri_is_segment(s + 1, second_sl - 1) && uri_is_path_abempty(s + second_sl, len - second_sl);
        }
    }
    return 0;
}

int uri_is_path(const char* s, int len) {
    return  uri_is_empty(s, len) || uri_is_path_absolute(s, len) || uri_is_path_abempty(s, len) ||
            uri_is_path_noscheme(s, len) || uri_is_path_rootless(s, len);
}

int uri_is_reg_name(const char* s, int len) {
    int i = 0;
    while (i < len) {
        if (uri_is_pct_encoded(s + i)) {
            if (i + 2 >= len) {
                return 0;
            }
            i += 3;
        }
        else if (uri_is_unreserved(*(s + i)) || uri_is_sub_delim(*(s + i))) {
            i += 1;
        }
        else {
            return 0;
        }
    }
    return 1;
}

int uri_is_dec_octet(const char* s, int len) {
    switch (len) {
        case 1:
            return abnf_is_DIGIT(*s);/*0-9*/
        case 2:
            return 0x31 <= *s && *s <= 0x39 && abnf_is_DIGIT(*(s + 1));/*1-9 0-9*/
        case 3:
            switch (*s) {
                case 0x31:
                    return abnf_is_DIGIT(*(s + 1)) && abnf_is_DIGIT(*(s + 2)); /*1 0-9 0-9*/
                case 0x32:
                    switch (*(s + 1)) {
                        case 0x30:
                        case 0x31:
                        case 0x32:
                        case 0x33:
                        case 0x34:
                            return abnf_is_DIGIT(*(s + 2)); /*2 0-4 0-9*/
                        case 0x35:
                            return 0x30 <= *(s + 2) && *(s + 2) <= 0x35; /*2 5 0-5*/
                        default:
                            return 0;
                    }
                default:
                    return 0;
            }
        default:
            return 0;
    }
    return 0;
}

int uri_is_IPv4address(const char* s, int len) {
    /*one past the index of previous "." or 0 in the beginning*/
    int past_prev_dot_index = 0;
    /*past_prev_dot_index + 1 i.e., we start looking for next "." from here*/
    int next_dot_index = 1;
    int i = 0;
    /*(dec-octet "." dec-octet "." dec-octet "." dec-octet) has 7-15 characters*/
    if (len < 7 || len > 15) {
        return 0;
    }
    for (i = 0; i < 3; ++i) { /*find and check first three 1*3DIGIT "."*/
        while (next_dot_index < len) {
            if (0x2E == *(s + next_dot_index) /*.*/) {
                break;
            }
            else {
                next_dot_index += 1;
            }
        }
        if (len == next_dot_index) {
            return 0;
        }
        else if (uri_is_dec_octet(s + pst_prev_dot_index, next_dot_index - past_prev_dot_index)) {
            past_prev_dot_index = next_dot_index + 1;
            next_dot_index = past_prev_dot_index + 1;
            continue;
        }
        else {
            return 0;
        }
    }
    /*the rest must be dec-octet*/
    return uri_is_dec_octet(s + past_prev_dot_index, len - past_prev_dot_index);
}

int uri_is_ls32(const char* s, int len) {
    int colon_index = 1;
    while (colon_index < len) {
        if (0x3A == *(s + colon_index) /*:*/) {
            break;
        }
        colon_index += 1;
    }
    if (colon_index >= len) { /*there is no ":", it has to be IPv4address*/
        return uri_is_IPv4address(s, len);
    }
    return uri_is_h16(s, colon_index) && uri_is_h16(s + colon_index + 1, len - (colon_index + 1));
}

int uri_is_h16(const char* s, int len) {
    /*1*4HEXDIG*/
    int i = 0;
    if (len < 1 || len > 4) {
        return 0;
    }
    while (i < len) {
        if (!abnf_is_HEXDIG(*(s + i))) {
            return 0;
        }
        i += 1;
    }
    return 1;
}

int uri_is_IPv6address(const char* s, int len) { //TODO
    int double_colon_index = 0;
    int has_dots = 0;
    while (dounle_colon_index + 1 < len) {
        if (    0x3A == *(s + double_colon_index) &&
                0x3A == *(s + double_colon_index + 1) /*::*/) {
            break;
        }
        double_colon_index += 1;
    }
    if (double_colon_index + 1 >= len) { /*6( h16 ":" ) ls32*/
        
    }
}

int uri_is_IPvFuture(const char* s, int len) { //TODO

}

int uri_is_IP_literal(const char* s, int len) {
    if (    len     <   3 ||
            0x5B    !=  *s /*[*/||
            0x5D    !=  *(s + len - 1)/*]*/) {
        return 0;
    }
    return uri_is_IPvFuture(s + 1, len - 2) || uri_is_IPv6address(s + 1, len - 2);
}

int uri_is_port(const char* s, int len) {
    int i = 0;
    while (i < len) {
        if (!anbf_is_DIGIT(*(s + i))) {
            return 0;
        }
        i += 1;
    }
    return 1;
}

int uri_is_host(const char* s, int len) {
    return uri_is_IP_literal(s, len) || uri_is_IPv4address(s, len) || uri_is_reg_name(s, len);
}

int uri_is_userinfo(const char* s, int len) {
    int i = 0;
    while (i < len) {
        if (uri_is_pct_encoded(s + i)) {
            if (i + 2 >= len) {
                return 0;
            }
            i += 3;
        }
        else if (   uri_is_unreserved(*(s + i)) ||
                    uri_is_sub_delim(*(s + i))  ||
                    0x3A == *(s + i) /*:*/) {
            i += 1;
        }
        else {
            return 0;
        }
    }
    return 1;
}

int uri_is_authority(const char* s, int len) { //TODO

}

int uri_is_scheme(const char* s, int len) {
    int i = 1;
    if (len < 1) {
        return 0;
    }
    if (!anbf_is_ALPHA(*s)) {
        return 0;
    }
    while (i < len) {
        if (!(anbf_is_ALPHA(*(s + i)) ||
              snbf_is_DIGIT(*(s + i)) ||
              0x2B == *(s + i) /*+*/||
              0x2D == *(s + i) /*-*/||
              0x2E == *(s + i) /*.*/)) {
            return 0;
        }
        i += 1;
    }
    return 1;
}

int uri_is_relative_part(const char* s, int len) { //TODO

}

int uri_is_relative_ref(const char* s, int len) {
    int query_start = -1;
    int fragment_start = -1;
    int i = 0;
    while (i < len) {
        if (query_start == -1 && 0x3F == *(s + i) /*?*/) {
            query_start = i;
        }
        if (fragment_start == -1 && 0x23 == *(s + i) /*#*/) {
            fragment_start = i;
        }
        i += 1;
    }
    /*if first ? is after first # there is no query it is a part of fragment*/
    if (fragment_start != -1 && query_start > fragment_start) {
        query_start = -1;
    }
    if (query_start == -1 && fragment_start == -1) { /*no query or fragment*/
        return uri_is_relative_part(s, len);
    }
    else if (query_start == -1) { /*no query*/
        return uri_is_relative_part(s, fragment_start) && uri_is_fragment(s + fragment_start + 1, len - (fragment_start + 1));
    }
    else if (fragment_start == -1) { /*no fragment*/
        return uri_is_relative_part(s, query_start) && uri_is_query(s + query_start + 1, len - (query_start + 1));
    }
    else { /*both query and fragment*/
        return uri_is_relative_part(s, query_start) && uri_is_query(s + query_start + 1, fragment_start - (query_start + 1)) && uri_is_fragment(s + fragment_start + 1, len - (fragment_start + 1));
    }
    return 0; /*it should never happen*/
}

int uri_is_absolute_uri(const char* s, int len);
int uri_is_uri_reference(const char* s, int len);
int uri_is_hier_part(const char* s, int len);
int uri_is_uri(const char* s, int len);

