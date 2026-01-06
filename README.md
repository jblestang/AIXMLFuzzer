# AIXMLFuzzer

A powerful XML fuzzer written in Rust that uses XSD (XML Schema Definition) files to generate mutated XML messages for testing and security analysis.

## Features

- **XSD Parsing**: Parses XSD schema files to understand valid XML structure
- **Valid XML Generation**: Generates valid XML documents based on XSD definitions
- **Multiple Fuzzing Strategies**:
  - **AddElement**: Adds unexpected or duplicate elements
  - **RemoveElement**: Removes required elements
  - **OutOfRangeValue**: Generates values outside allowed ranges (numeric constraints)
  - **InvalidEnum**: Uses invalid enumeration values
  - **InvalidAttribute**: Adds invalid or malicious attributes
  - **MissingRequiredAttribute**: Removes required attributes
  - **InvalidType**: Replaces values with incorrect data types
  - **MalformedXml**: Creates syntactically invalid XML
  - **ExtremeValues**: Uses extreme numeric values
  - **BoundaryValues**: Tests boundary conditions (min/max values)

## Installation

```bash
cargo build --release
```

## Usage

### Basic Usage

Generate fuzzed XML files from an XSD schema:

```bash
cargo run --release -- --xsd example.xsd --root Person --count 10
```

### Generate Valid XML

Generate valid XML instead of fuzzed:

```bash
cargo run --release -- --xsd example.xsd --root Person --valid --count 5
```

### Specific Fuzzing Strategy

Use a specific fuzzing strategy:

```bash
cargo run --release -- --xsd example.xsd --root Person --strategy OutOfRangeValue --count 10
```

### All Strategies

Generate XML files using all fuzzing strategies:

```bash
cargo run --release -- --xsd example.xsd --root Person --strategy All --count 5
```

### Custom Output Directory

Specify a custom output directory:

```bash
cargo run --release -- --xsd example.xsd --root Person --output ./fuzzed_xml --count 20
```

## Command Line Options

- `--xsd, -x`: Path to the XSD schema file (required)
- `--root, -r`: Root element name to generate/fuzz (required)
- `--output, -o`: Output directory for generated XML files (default: `output`)
- `--strategy, -s`: Fuzzing strategy to use (optional)
- `--count, -c`: Number of fuzzed XML files to generate (default: 10)
- `--valid`: Generate valid XML instead of fuzzed

## Available Fuzzing Strategies

1. **AddElement**: Adds unexpected elements to the XML structure
2. **RemoveElement**: Removes elements that may be required
3. **OutOfRangeValue**: Generates numeric values outside the allowed range
4. **InvalidEnum**: Uses enumeration values that are not in the allowed set
5. **InvalidAttribute**: Adds invalid or potentially malicious attributes
6. **MissingRequiredAttribute**: Removes attributes marked as required
7. **InvalidType**: Replaces values with incorrect data types
8. **MalformedXml**: Creates XML with syntax errors
9. **ExtremeValues**: Uses very large or very small numeric values
10. **BoundaryValues**: Tests min/max boundary conditions

## Example XSD Schema

See `example.xsd` for a sample XSD schema that demonstrates various features:
- Complex types with sequences
- Simple types with restrictions
- Numeric constraints (min/max)
- Enumerations
- Required attributes
- Optional elements

## How It Works

1. **XSD Parsing**: The tool parses the XSD file to extract:
   - Element definitions and their types
   - Type restrictions (min/max values, enumerations, patterns)
   - Attribute definitions and requirements
   - Element relationships (sequences, choices, etc.)

2. **Valid XML Generation**: Based on the parsed schema, generates valid XML that conforms to all constraints.

3. **Fuzzing**: Applies various mutation strategies to create invalid or unexpected XML that can help discover:
   - Parsing vulnerabilities
   - Validation bypasses
   - Edge case handling issues
   - Security vulnerabilities

## Use Cases

- **Security Testing**: Find vulnerabilities in XML parsers and validators
- **Quality Assurance**: Test XML processing applications with edge cases
- **Compliance Testing**: Verify that XML validators properly reject invalid input
- **Fuzzing**: Generate test cases for automated fuzzing campaigns

## Requirements

- Rust 1.70 or later
- Cargo package manager

## License

This project is provided as-is for educational and testing purposes.

