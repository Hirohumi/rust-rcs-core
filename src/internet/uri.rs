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

use super::parameter::ParameterParser;

// to-do: change &[u8] for &str
pub enum URIPath<'a> {
    AbEmpty(&'a [u8], Option<&'a [u8]>), // "//" authority *( "/" segment )
    Absolute(&'a [u8]),                  // "/" [ segment-nz *( "/" segment ) ]
    Rootless(&'a [u8]),                  // segment-nz *( "/" segment )
    NoScheme(&'a [u8]),                  // segment-nz-nc *( "/" segment )
    Empty(),
}

pub enum URI<'a> {
    // scheme ":" hier-part [ "?" query ] [ "#" fragment ]
    // hier-part = "//" authority path-abempty
    //           / path-absolute
    //           / path-rootless
    //           / path-empty
    Standard(&'a [u8], URIPath<'a>, Option<&'a [u8]>, Option<&'a [u8]>),
    // relative-part [ "?" query ] [ "#" fragment ]
    // relative-part = "//" authority path-abempty
    //               / path-absolute
    //               / path-noscheme
    //               / path-empty
    Relative(URIPath<'a>, Option<&'a [u8]>, Option<&'a [u8]>),
}

impl URI<'_> {
    pub fn is_absolute(&self) -> bool {
        match self {
            URI::Standard(_, _, _, fragment) => match fragment {
                Some(_) => false,
                None => true,
            },
            _ => false,
        }
    }

    pub fn get_query_value<'b>(&self, query_name: &'b [u8]) -> Option<&[u8]> {
        if let Some(query_part) = match self {
            URI::Standard(_, _, query, _) => *query,
            URI::Relative(_, query, _) => *query,
        } {
            for query_parameter in ParameterParser::new(query_part, b'&', false) {
                if query_parameter.name.eq_ignore_ascii_case(query_name) {
                    if query_parameter.value.is_none() {
                        return Some(&[]);
                    } else {
                        return query_parameter.value;
                    }
                }
            }
        }

        None
    }

    pub fn string_representation_without_query_and_fragment(&self) -> Vec<u8> {
        match self {
            URI::Standard(scheme, hier_part, _, _) => {
                let mut uri_string = Vec::new();
                uri_string.extend_from_slice(scheme);
                uri_string.extend(b":");
                match hier_part {
                    URIPath::AbEmpty(authority, path) => {
                        uri_string.extend(b"//");
                        uri_string.extend_from_slice(authority);
                        if let Some(path) = path {
                            uri_string.extend(b"/");
                            uri_string.extend_from_slice(path);
                        }
                        uri_string
                    }
                    URIPath::Absolute(path) => {
                        uri_string.extend(b"/");
                        uri_string.extend_from_slice(path);
                        uri_string
                    }
                    URIPath::Rootless(path) => {
                        uri_string.extend_from_slice(path);
                        uri_string
                    }
                    _ => uri_string,
                }
            }

            URI::Relative(path, _, _) => {
                let mut uri_string = Vec::new();
                match path {
                    URIPath::AbEmpty(authority, path) => {
                        uri_string.extend(b"//");
                        uri_string.extend_from_slice(authority);
                        if let Some(path) = path {
                            uri_string.extend(b"/");
                            uri_string.extend_from_slice(path);
                        }
                        uri_string
                    }
                    URIPath::Absolute(path) => {
                        uri_string.extend(b"/");
                        uri_string.extend_from_slice(path);
                        uri_string
                    }
                    URIPath::NoScheme(path) => {
                        uri_string.extend_from_slice(path);
                        uri_string
                    }
                    _ => uri_string,
                }
            }
        }
    }
}

pub trait AsURI<'a> {
    type Target;
    fn as_standard_uri(&'a self) -> Option<Self::Target>;
}

impl<'a> AsURI<'a> for [u8] {
    type Target = URI<'a>;
    fn as_standard_uri(&'a self) -> Option<URI<'a>> {
        if let Some(position) = self.iter().position(|c| *c == b':') {
            let scheme = &self[..position];

            let mut query: Option<&'a [u8]> = None;
            let mut fragment: Option<&'a [u8]> = None;

            let hierarchical_part_and_query_and_fragment = &self[position + 1..];

            let hierarchical_part_and_query: &'a [u8];

            if let Some(begin_of_fragment) = hierarchical_part_and_query_and_fragment
                .iter()
                .position(|c| *c == b'#')
            {
                hierarchical_part_and_query =
                    &hierarchical_part_and_query_and_fragment[..begin_of_fragment];
                fragment = Some(&hierarchical_part_and_query_and_fragment[begin_of_fragment + 1..]);
            } else {
                hierarchical_part_and_query = hierarchical_part_and_query_and_fragment;
            }

            let hierarchical_part: &'a [u8];

            if let Some(begin_of_query) =
                hierarchical_part_and_query.iter().position(|c| *c == b'?')
            {
                hierarchical_part = &hierarchical_part_and_query[..begin_of_query];
                query = Some(&hierarchical_part_and_query[begin_of_query + 1..]);
            } else {
                hierarchical_part = hierarchical_part_and_query
            }

            if hierarchical_part.starts_with(b"//") {
                let part = &hierarchical_part[2..];
                if let Some(begin_of_path) = part.iter().position(|c| *c == b'/') {
                    let authority = &part[..begin_of_path];
                    let path = Some(&part[begin_of_path + 1..]);
                    return Some(URI::Standard(
                        scheme,
                        URIPath::AbEmpty(authority, path),
                        query,
                        fragment,
                    ));
                } else {
                    return Some(URI::Standard(
                        scheme,
                        URIPath::AbEmpty(part, None),
                        query,
                        fragment,
                    ));
                }
            } else if hierarchical_part.starts_with(b"/") {
                let segments = &hierarchical_part[1..];
                return Some(URI::Standard(
                    scheme,
                    URIPath::Absolute(segments),
                    query,
                    fragment,
                ));
            } else if hierarchical_part.len() > 0 {
                return Some(URI::Standard(
                    scheme,
                    URIPath::Rootless(hierarchical_part),
                    query,
                    fragment,
                ));
            } else if hierarchical_part.len() == 0 {
                return Some(URI::Standard(scheme, URIPath::Empty(), query, fragment));
            }
        }

        None
    }
}
