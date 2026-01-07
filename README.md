# AIXMLFuzzer

A powerful XML fuzzer written in Rust that uses XSD (XML Schema Definition) files to generate mutated XML messages for testing and security analysis. The tool automatically discovers all constraint violations in an XSD schema and generates test cases for each one.

## Features

- **Comprehensive XSD Parsing**: Parses XSD schema files to understand valid XML structure, including:
  - Complex and simple types
  - Namespace support (targetNamespace, elementFormDefault)
  - Type restrictions and facets
  - Element and attribute definitions
  - Sequence, choice, and all constraints
  - Groups and attribute groups
  - Key, unique, and keyref constraints

- **Valid XML Generation**: Generates valid XML documents based on XSD definitions with proper namespace declarations

- **Automatic Constraint Discovery**: Automatically discovers all constraint violations in the XSD schema

- **Sequential Violation Generation**: Generates one XML file per constraint violation, ensuring comprehensive coverage

- **30+ Fuzzing Strategies**: Comprehensive coverage of XSD constraints including:
  - **Occurrence Constraints**: minOccurs, maxOccurs
  - **Length Constraints**: minLength, maxLength, length
  - **Numeric Constraints**: minInclusive, maxInclusive, minExclusive, maxExclusive
  - **Pattern Constraints**: Regular expression patterns
  - **Digit Constraints**: totalDigits, fractionDigits
  - **Enumeration Constraints**: Invalid enumeration values
  - **Structural Constraints**: sequence order, choice, all
  - **Attribute Constraints**: Required attributes, default values, fixed values
  - **Type Constraints**: Abstract types, mixed content, union, list
  - **Advanced Constraints**: unique, key, keyref, substitution groups, xsi:type

- **Validation Script**: Included script to validate generated violations against the XSD schema

## Installation

```bash
cargo build --release
```

## Usage

### Generate All Constraint Violations (Recommended)

Automatically discover and generate one XML file for each constraint violation in the schema:

```bash
./target/release/aixmlfuzzer --xsd example.xsd --root Person --all-violations --output output
```

This will:
1. Parse the XSD schema
2. Discover all constraint violations (e.g., minOccurs, maxOccurs, minLength, enumeration, etc.)
3. Generate one XML file per violation, applying only that specific violation
4. Save all files to the output directory

### Validate Generated Violations

Use the included validation script to verify that all generated violations are indeed invalid:

```bash
./validate_violations.sh example.xsd output
```

This script:
- Validates each generated XML file against the XSD schema
- Reports which violations are valid (correctly fail validation)
- Shows detailed error messages from the validator
- Provides a summary of validation results

### Generate Valid XML

Generate valid XML instead of fuzzed:

```bash
./target/release/aixmlfuzzer --xsd example.xsd --root Person --valid --count 5
```

### Specific Fuzzing Strategy

Use a specific fuzzing strategy:

```bash
./target/release/aixmlfuzzer --xsd example.xsd --root Person --strategy violate-min-inclusive --count 10
```

### All Strategies

Generate XML files using all fuzzing strategies:

```bash
./target/release/aixmlfuzzer --xsd example.xsd --root Person --strategy all --count 5
```

### Custom Output Directory

Specify a custom output directory:

```bash
./target/release/aixmlfuzzer --xsd example.xsd --root Person --output ./fuzzed_xml --count 20
```

## Command Line Options

- `--xsd, -x`: Path to the XSD schema file (required)
- `--root, -r`: Root element name to generate/fuzz (required)
- `--output, -o`: Output directory for generated XML files (default: `output`)
- `--strategy, -s`: Fuzzing strategy to use (optional, see available strategies below)
- `--count, -c`: Number of fuzzed XML files to generate (default: 10)
- `--valid`: Generate valid XML instead of fuzzed
- `--all-violations`: Automatically discover and generate all constraint violations (one per file)

## Available Fuzzing Strategies

### Basic Strategies
- `add-element`: Adds unexpected elements to the XML structure
- `remove-element`: Removes elements that may be required
- `out-of-range-value`: Generates numeric values outside the allowed range
- `invalid-enum`: Uses enumeration values that are not in the allowed set
- `invalid-attribute`: Adds invalid or potentially malicious attributes
- `missing-required-attribute`: Removes attributes marked as required
- `invalid-type`: Replaces values with incorrect data types
- `malformed-xml`: Creates XML with syntax errors
- `extreme-values`: Uses very large or very small numeric values
- `boundary-values`: Tests min/max boundary conditions

### XSD Constraint Violations
- `violate-min-occurs`: Violates minimum occurrence constraints
- `violate-max-occurs`: Violates maximum occurrence constraints
- `violate-min-length`: Violates minimum length constraints
- `violate-max-length`: Violates maximum length constraints
- `violate-length`: Violates exact length constraints
- `violate-min-inclusive`: Violates minimum inclusive value constraints
- `violate-max-inclusive`: Violates maximum inclusive value constraints
- `violate-min-exclusive`: Violates minimum exclusive value constraints
- `violate-max-exclusive`: Violates maximum exclusive value constraints
- `violate-pattern`: Violates regular expression pattern constraints
- `violate-total-digits`: Violates total digits constraints
- `violate-fraction-digits`: Violates fraction digits constraints
- `violate-choice`: Violates choice constraints
- `violate-sequence-order`: Violates sequence order constraints
- `violate-fixed-value`: Violates fixed value constraints
- `violate-nillable`: Violates nillable constraints
- `violate-white-space`: Violates whitespace handling constraints
- `violate-all`: Violates all constraints
- `violate-unique`: Violates unique constraints
- `violate-key`: Violates key constraints
- `violate-keyref`: Violates key reference constraints
- `violate-default`: Violates default value constraints
- `violate-abstract`: Violates abstract type constraints
- `violate-mixed`: Violates mixed content constraints
- `violate-union`: Violates union type constraints
- `violate-list`: Violates list type constraints
- `violate-any`: Violates any element constraints
- `violate-any-attribute`: Violates any attribute constraints
- `violate-xsi-type`: Violates xsi:type constraints
- `violate-substitution-group`: Violates substitution group constraints

## Example XSD Schema

See `example.xsd` for a sample XSD schema that demonstrates various features:
- Complex types with sequences
- Simple types with restrictions
- Numeric constraints (min/max inclusive)
- String length constraints (minLength, maxLength)
- Enumerations
- Required and optional attributes
- Optional elements
- Decimal types with totalDigits and fractionDigits
- Namespace support (targetNamespace)

## How It Works

1. **XSD Parsing**: The tool parses the XSD file to extract:
   - Element definitions and their types
   - Type restrictions (min/max values, enumerations, patterns, digits)
   - Attribute definitions and requirements
   - Element relationships (sequences, choices, all)
   - Namespace declarations and target namespaces
   - Complex type structures and inheritance

2. **Valid XML Generation**: Based on the parsed schema, generates valid XML that:
   - Conforms to all constraints
   - Includes proper namespace declarations
   - Respects minOccurs/maxOccurs constraints
   - Uses valid enumeration values
   - Includes required attributes

3. **Constraint Discovery**: Automatically discovers all constraint violations by:
   - Recursively traversing the schema structure
   - Identifying all elements with constraints
   - Building a list of all possible violations

4. **Violation Generation**: For each discovered constraint:
   - Generates a valid XML base
   - Applies exactly one constraint violation
   - Saves to a uniquely named file

5. **Fuzzing**: Applies various mutation strategies to create invalid or unexpected XML that can help discover:
   - Parsing vulnerabilities
   - Validation bypasses
   - Edge case handling issues
   - Security vulnerabilities

## Validation

The included `validate_violations.sh` script validates all generated XML files against the XSD schema using `xmllint`. It:
- Checks each generated violation file
- Reports validation errors with full error messages
- Provides a summary of valid vs invalid violations
- Uses color-coded output for easy reading

Example output:
```
✓ violation_0010_Person_age_minInclusive.xml - Valid violation:
  element age: Schemas validity error : Element '{http://example.com/person}age': [facet 'minInclusive'] The value '-1' is less than the minimum value allowed ('0').
```

## XSD Constraint Coverage

The fuzzer supports testing of 30+ XSD constraint types. See `XSD_CONSTRAINTS_ANALYSIS.md` for a complete analysis of:
- Currently implemented constraints
- Constraints parsed but not fully tested
- Missing constraints and recommendations

## Use Cases

- **Security Testing**: Find vulnerabilities in XML parsers and validators
- **Quality Assurance**: Test XML processing applications with edge cases
- **Compliance Testing**: Verify that XML validators properly reject invalid input
- **Fuzzing**: Generate comprehensive test cases for automated fuzzing campaigns
- **Schema Testing**: Validate that XSD schemas correctly define constraints

## Requirements

- Rust 1.70 or later
- Cargo package manager
- `xmllint` (for validation script, typically included with libxml2)

## Project Structure

```
.
├── src/
│   ├── main.rs          # CLI interface
│   ├── lib.rs           # Library exports
│   ├── xsd.rs           # XSD schema parser
│   ├── xml_generator.rs # Valid XML generator
│   └── fuzzer.rs        # Fuzzing strategies and violation generation
├── example.xsd          # Example XSD schema
├── validate_violations.sh # Validation script
└── XSD_CONSTRAINTS_ANALYSIS.md # Constraint coverage analysis
```

## License

This project is provided as-is for educational and testing purposes.
