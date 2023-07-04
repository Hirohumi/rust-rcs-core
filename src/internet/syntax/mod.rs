// Copyright 2023 宋昊文
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::borrow::Cow;

/// Adding quote to a string if neccessary so that it can be correctly used in a internet message header parameter field
///
/// # Examples
///
/// ```
/// let a = "sip:bj.ims.mnc000.mcc460.3gppnetwork.org";
/// let b = "\"sip:bj.ims.mnc000.mcc460.3gppnetwork.org\"";
///
/// let slice_a = rust_rcs_core::internet::syntax::quote(a);
/// let slice_b = rust_rcs_core::internet::syntax::quote(b);
///
/// assert_eq!(slice_a, b);
/// assert_eq!(slice_b, b);
///
/// let c = "AKAv1-MD5";
/// let d = "\"AKAv1-MD5\"";
///
/// let slice_c = rust_rcs_core::internet::syntax::quote(c);
/// let slice_d = rust_rcs_core::internet::syntax::quote(d);
///
/// assert_eq!(slice_c, c);
/// assert_eq!(slice_d, d);
/// ```
pub fn quote(s: &str) -> Cow<str> {
    // to-do: &[u8] version needed
    if s.len() == 0 {
        return Cow::Borrowed(&"\"\"");
    }

    if s.len() >= 2 && s.starts_with("\"") && s.ends_with("\"") {
        return Cow::Borrowed(s);
    }

    if s.contains("(")
        || s.contains(")")
        || s.contains("<")
        || s.contains(">")
        || s.contains("[")
        || s.contains("]")
        || s.contains(":")
        || s.contains(";")
        || s.contains("@")
        || s.contains("\\")
        || s.contains(",")
        || s.contains(".")
        || s.contains("\"")
        || s.contains("=")
    {
        let s = format!("\"{}\"", s);

        return Cow::Owned(s);
    }

    Cow::Borrowed(s)
}

/// Unquote a string to retrieve its literal value
///
/// # Examples
///
/// ```
/// let a = b"\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"";
///
/// let slice = rust_rcs_core::internet::syntax::unquote(a);
///
/// assert_eq!(slice, b"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session");
/// ```
pub fn unquote(s: &[u8]) -> &[u8] {
    if s.len() >= 2 && s.starts_with(b"\"") && s.ends_with(b"\"") {
        return &s[1..s.len() - 1];
    }

    s
}

/// Remove wrapping brackets from a string to retrieve its literal value
///
/// # Examples
///
/// ```
/// let a = b"<urn:ietf:params:imdn>";
///
/// let slice = rust_rcs_core::internet::syntax::undo_bracket(a);
///
/// assert_eq!(slice, b"urn:ietf:params:imdn");
/// ```
pub fn undo_bracket(s: &[u8]) -> &[u8] {
    if s.len() >= 2 && s.starts_with(b"<") && s.ends_with(b">") {
        return &s[1..s.len() - 1];
    }

    s
}

/// Trim a string from both starting and ending white spaces
///
/// # Examples
///
/// ```
/// let a = b" Hello, World! ";
///
/// let slice = rust_rcs_core::internet::syntax::trim(a);
///
/// assert_eq!(slice, b"Hello, World!");
/// ```
///
/// Trimming a string full of white spaces should yield an empty slice
///
/// ```
/// let a = b"    \t   ";
///
/// let slice = rust_rcs_core::internet::syntax::trim(a);
///
/// assert_eq!(slice, b"");
/// ```
pub fn trim(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == b' ' || c == b'\t' {
            i = i + 1;
            continue;
        }
        break;
    }
    let mut j = s.len();
    while j > i {
        let c = s[j - 1];
        if c == b' ' || c == b'\t' {
            j = j - 1;
            continue;
        }
        break;
    }
    &s[i..j]
}

/// Find index of a ascii character that forms a language construct,
/// quoted characters are opaque tokens by definition, therefore are not taken into account
///
/// # Examples
///
/// ```
/// let a = b"<urn:ietf:params:imdn>";
///
/// let b = &a[1..]; // "urn:ietf:params:imdn>"
///
/// if let Some(idx) = rust_rcs_core::internet::syntax::index_with_character_escaping(b, b'>') {
///     assert_eq!(idx, 20);
///     assert_eq!(&a[1..1+idx], b"urn:ietf:params:imdn");
/// } else {
///     panic!("not found!\n");
/// }
/// ```
pub fn index_with_character_escaping(s: &[u8], b: u8) -> Option<usize> {
    let mut i = 0;

    while i < s.len() {
        let c = s[i];

        if c == b'\\' {
            i = i + 2;
            continue;
        }

        if c == b {
            return Some(i);
        }

        i = i + 1;
    }

    None
}

/// Find index of a ascii character that forms a language construct,
/// bypass all tokens that are bracket or double quoted
///
/// # Examples
///
/// ```
/// let a = b"<sip:anonymous@anonymous.invalid;transport=tcp>;+sip.instance=\"<urn:uuid:e283b49b-8999-475d-c708-0805e279b4d1>\";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg\"";
///
/// if let Some(idx) = rust_rcs_core::internet::syntax::index_with_token_escaping(a, b';') {
///     assert_eq!(idx, 47);
///     assert_eq!(&a[..idx], b"<sip:anonymous@anonymous.invalid;transport=tcp>");
///
///     let b = &a[48..]; // "+sip.instance=\"<urn:uuid:e283b49b-8999-475d-c708-0805e279b4d1>\";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg\""
///
///     if let Some(idx) = rust_rcs_core::internet::syntax::index_with_token_escaping(b, b';') {
///         assert_eq!(idx, 63);
///         assert_eq!(&b[..idx], b"+sip.instance=\"<urn:uuid:e283b49b-8999-475d-c708-0805e279b4d1>\"");
///     } else {
///         panic!("not found @2!\n");
///     }
///
/// } else {
///     panic!("not found @1!\n");
/// }
/// ```
pub fn index_with_token_escaping(s: &[u8], b: u8) -> Option<usize> {
    let mut i = 0;

    while i < s.len() {
        let c = s[i];

        if c == b {
            return Some(i);
        }

        if c == b'\"' {
            match index_with_character_escaping(&s[i + 1..], b'\"') {
                Some(idx) => i = i + 1 + idx + 1,
                None => return None,
            }
        } else if c == b'<' {
            match index_with_character_escaping(&s[i + 1..], b'>') {
                Some(idx) => i = i + 1 + idx + 1,
                None => return None,
            }
        } else {
            i = i + 1;
        }
    }

    None
}

/// Find index of first charater after OWS(optional white spaces) or Obsolete line folding
///
/// # Examples
///
/// ```
/// let a = b"Newauth realm=\"apps\", type=1,\n                       title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"\n";
///
/// let b = &a[29..]; // "\n                       title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"\n"
///
/// let idx = rust_rcs_core::internet::syntax::index_skipping_ows_and_obs_fold(b);
///
/// assert_eq!(idx, 24);
/// assert_eq!(&b[idx..], b"title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"");
/// ```
pub fn index_skipping_ows_and_obs_fold(s: &[u8]) -> usize {
    let mut i = 0;

    while i < s.len() {
        let c = s[i];

        if c == b'\n' {
            if i + 1 < s.len() {
                let ws = s[i + 1];
                if ws == b' ' || ws == b'\t' {
                    i = i + 2;
                    continue;
                } else {
                    return i;
                }
            } else {
                return i;
            }
        } else if c != b' ' && c != b'\t' {
            return i;
        }

        i = i + 1;
    }

    i
}

/// Find index of first charater after padding white spaces and CRLFs
///
/// # Examples
///
/// ```
/// let a = b"Content-Type: multipart/mixed; boundary=next\r\n    \r\n    \r\n--next\r\n";
///
/// let b = &a[46..]; // "    \r\n    \r\n--next\r\n"
///
/// let idx = rust_rcs_core::internet::syntax::index_skipping_transport_padding_and_crlf(b);
///
/// assert_eq!(idx, 12);
/// assert_eq!(&b[idx..], b"--next\r\n");
/// ```
pub fn index_skipping_transport_padding_and_crlf(s: &[u8]) -> usize {
    let mut i = 0;

    while i < s.len() {
        let cr = s[i];

        if cr != b' ' && cr != b'\t' {
            if cr == b'\r' {
                if i + 1 < s.len() {
                    let lf = s[i + 1];

                    if lf == b'\n' {
                        if i + 2 < s.len() {
                            let wsp = s[i + 2];

                            if wsp == b' ' || wsp == b'\t' {
                                i = i + 3;
                                continue;
                            }
                        }

                        return i + 2;
                    }
                }
            }

            return i;
        }

        i = i + 1;
    }

    i
}
