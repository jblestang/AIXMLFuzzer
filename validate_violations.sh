#!/bin/bash

# Script to validate that XML files in output/ directory are valid violations of the XSD schema
# A valid violation should FAIL xmllint validation

# Don't use set -e because we expect xmllint to fail for violations

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default XSD file
XSD_FILE="${1:-example.xsd}"
OUTPUT_DIR="${2:-output}"

# Check if xmllint is available
if ! command -v xmllint &> /dev/null; then
    echo -e "${RED}Error: xmllint is not installed${NC}"
    echo "Please install libxml2-utils (on Ubuntu/Debian) or libxml2 (on macOS with Homebrew)"
    exit 1
fi

# Check if XSD file exists
if [ ! -f "$XSD_FILE" ]; then
    echo -e "${RED}Error: XSD file '$XSD_FILE' not found${NC}"
    exit 1
fi

# Check if output directory exists
if [ ! -d "$OUTPUT_DIR" ]; then
    echo -e "${RED}Error: Output directory '$OUTPUT_DIR' not found${NC}"
    exit 1
fi

echo "Validating violations in $OUTPUT_DIR/ against $XSD_FILE"
echo "=================================================="
echo ""

# Counters
TOTAL=0
VALID_VIOLATIONS=0
INVALID_VIOLATIONS=0
MALFORMED_XML=0

# Process each XML file in output directory
for xml_file in "$OUTPUT_DIR"/*.xml; do
    # Skip if no XML files found
    [ -f "$xml_file" ] || continue
    
    TOTAL=$((TOTAL + 1))
    filename=$(basename "$xml_file")
    
    # Validate XML against XSD
    # xmllint returns non-zero exit code if validation fails (which is what we want for violations)
    validation_output=$(xmllint --noout --schema "$XSD_FILE" "$xml_file" 2>&1)
    exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        # Validation passed - this is BAD, it means the violation didn't work
        echo -e "${RED}✗ $filename - Validation PASSED (should have failed!)${NC}"
        INVALID_VIOLATIONS=$((INVALID_VIOLATIONS + 1))
    else
        # Check if it's a validation error (exit code 3) or malformed XML (exit code 1)
        if [ $exit_code -eq 3 ]; then
            # Exit code 3 means validation error - this is GOOD for violations
            # Extract the actual validation error message (first line with "error")
            error_msg=$(echo "$validation_output" | grep -i "error" | head -1 | cut -d: -f3- | cut -c1-60)
            if [ -n "$error_msg" ]; then
                echo -e "${GREEN}✓ $filename - Valid violation: ${error_msg}...${NC}"
            else
                echo -e "${GREEN}✓ $filename - Valid violation (validation failed as expected)${NC}"
            fi
            VALID_VIOLATIONS=$((VALID_VIOLATIONS + 1))
        elif [ $exit_code -eq 1 ]; then
            # Exit code 1 might mean malformed XML or namespace issues
            # Check if it's a namespace issue (which is still a valid violation)
            if echo "$validation_output" | grep -qi "namespace\|declaration"; then
                echo -e "${GREEN}✓ $filename - Valid violation (namespace/declaration error)${NC}"
                VALID_VIOLATIONS=$((VALID_VIOLATIONS + 1))
            else
                echo -e "${YELLOW}⚠ $filename - Malformed XML or parsing error${NC}"
                MALFORMED_XML=$((MALFORMED_XML + 1))
            fi
        else
            # Other error - still consider it a violation if it mentions validation
            if echo "$validation_output" | grep -qi "valid\|error\|fail"; then
                echo -e "${GREEN}✓ $filename - Valid violation (validation error)${NC}"
                VALID_VIOLATIONS=$((VALID_VIOLATIONS + 1))
            else
                echo -e "${YELLOW}⚠ $filename - Unexpected error (exit code: $exit_code)${NC}"
                MALFORMED_XML=$((MALFORMED_XML + 1))
            fi
        fi
    fi
done

echo ""
echo "=================================================="
echo "Summary:"
echo -e "  Total files: $TOTAL"
echo -e "  ${GREEN}Valid violations: $VALID_VIOLATIONS${NC}"
echo -e "  ${RED}Invalid violations (should fail but passed): $INVALID_VIOLATIONS${NC}"
echo -e "  ${YELLOW}Malformed XML or errors: $MALFORMED_XML${NC}"
echo ""

# Exit with error if there are invalid violations
if [ $INVALID_VIOLATIONS -gt 0 ]; then
    echo -e "${RED}ERROR: Some violations are not working correctly!${NC}"
    exit 1
fi

if [ $TOTAL -eq 0 ]; then
    echo -e "${YELLOW}WARNING: No XML files found in $OUTPUT_DIR/${NC}"
    exit 1
fi

echo -e "${GREEN}All violations are valid!${NC}"
exit 0

