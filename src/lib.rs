//! XML Fuzzer Library
//! 
//! This library provides functionality to parse XSD schemas and generate
//! both valid and fuzzed XML documents based on the schema definitions.

/// XSD schema parsing module
/// Handles parsing of XML Schema Definition files into internal data structures
pub mod xsd;

/// XML generation module
/// Generates valid XML documents conforming to the parsed XSD schema
pub mod xml_generator;

/// Fuzzing module
/// Implements various fuzzing strategies to generate invalid XML for testing
pub mod fuzzer;

// Re-export all public types and functions for convenience
pub use xsd::*;
pub use xml_generator::*;
pub use fuzzer::*;

