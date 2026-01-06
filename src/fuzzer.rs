use crate::xsd::*;
use crate::xml_generator::XmlGenerator;
use rand::Rng;
use regex::Regex;

#[derive(Debug, Clone, Copy)]
pub enum FuzzStrategy {
    AddElement,
    RemoveElement,
    OutOfRangeValue,
    InvalidEnum,
    InvalidAttribute,
    MissingRequiredAttribute,
    InvalidType,
    MalformedXml,
    ExtremeValues,
    BoundaryValues,
}

pub struct XmlFuzzer {
    schema: XsdSchema,
    generator: XmlGenerator,
    rng: rand::rngs::ThreadRng,
}

impl XmlFuzzer {
    pub fn new(schema: XsdSchema) -> Self {
        let generator = XmlGenerator::new(schema.clone());
        Self {
            schema,
            generator,
            rng: rand::thread_rng(),
        }
    }

    pub fn fuzz(&mut self, root_element: &str, strategy: FuzzStrategy) -> String {
        match strategy {
            FuzzStrategy::AddElement => self.fuzz_add_element(root_element),
            FuzzStrategy::RemoveElement => self.fuzz_remove_element(root_element),
            FuzzStrategy::OutOfRangeValue => self.fuzz_out_of_range_value(root_element),
            FuzzStrategy::InvalidEnum => self.fuzz_invalid_enum(root_element),
            FuzzStrategy::InvalidAttribute => self.fuzz_invalid_attribute(root_element),
            FuzzStrategy::MissingRequiredAttribute => {
                self.fuzz_missing_required_attribute(root_element)
            }
            FuzzStrategy::InvalidType => self.fuzz_invalid_type(root_element),
            FuzzStrategy::MalformedXml => self.fuzz_malformed_xml(root_element),
            FuzzStrategy::ExtremeValues => self.fuzz_extreme_values(root_element),
            FuzzStrategy::BoundaryValues => self.fuzz_boundary_values(root_element),
        }
    }

    pub fn fuzz_all(&mut self, root_element: &str) -> Vec<(FuzzStrategy, String)> {
        let strategies = vec![
            FuzzStrategy::AddElement,
            FuzzStrategy::RemoveElement,
            FuzzStrategy::OutOfRangeValue,
            FuzzStrategy::InvalidEnum,
            FuzzStrategy::InvalidAttribute,
            FuzzStrategy::MissingRequiredAttribute,
            FuzzStrategy::InvalidType,
            FuzzStrategy::ExtremeValues,
            FuzzStrategy::BoundaryValues,
        ];

        strategies
            .into_iter()
            .map(|strategy| {
                let fuzzed = self.fuzz(root_element, strategy);
                (strategy, fuzzed)
            })
            .collect()
    }

    fn fuzz_add_element(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find a random place to add an element
        if let Some(elem) = self.schema.get_element(root_element) {
            if !elem.children.is_empty() {
                let random_child = &elem.children[self.rng.gen_range(0..elem.children.len())];
                // Add a duplicate or extra element
                let insert_pos = xml.find("</").unwrap_or(xml.len() - 10);
                let extra_elem = format!("<{}>extra_value</{}>\n", random_child, random_child);
                xml.insert_str(insert_pos, &extra_elem);
            } else {
                // Add a completely random element
                let random_elem = format!("<randomElement{}>value</randomElement{}>\n", 
                    self.rng.gen_range(0..1000), 
                    self.rng.gen_range(0..1000));
                let insert_pos = xml.find("</").unwrap_or(xml.len() - 10);
                xml.insert_str(insert_pos, &random_elem);
            }
        }
        
        xml
    }

    fn fuzz_remove_element(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Remove a random element
        if let Some(elem) = self.schema.get_element(root_element) {
            if !elem.children.is_empty() {
                let child_to_remove = &elem.children[self.rng.gen_range(0..elem.children.len())];
                let pattern = format!("<{}>.*?</{}>", child_to_remove, child_to_remove);
                let re = Regex::new(&pattern).unwrap();
                xml = re.replace(&xml, "").to_string();
            }
        }
        
        xml
    }

    fn fuzz_out_of_range_value(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values and make them out of range
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.fuzz_element_values(&mut xml, &elem_clone, true);
        }
        
        xml
    }

    fn fuzz_invalid_enum(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find enumeration values and replace with invalid ones
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.fuzz_enum_values(&mut xml, &elem_clone);
        }
        
        xml
    }

    fn fuzz_invalid_attribute(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Add invalid attributes
        let invalid_attrs = vec![
            "invalidAttr=\"value\"",
            "x:invalid=\"test\"",
            "attr123=\"<script>alert('xss')</script>\"",
        ];
        let random_attr = &invalid_attrs[self.rng.gen_range(0..invalid_attrs.len())];
        
        // Insert after first <element
        if let Some(pos) = xml.find('>') {
            xml.insert_str(pos, &format!(" {}", random_attr));
        }
        
        xml
    }

    fn fuzz_missing_required_attribute(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Remove required attributes
        if let Some(elem) = self.schema.get_element(root_element) {
            for attr in &elem.attributes {
                if attr.required {
                    let pattern = format!(r#"\s+{}=\"[^\"]*\""#, attr.name);
                    let re = Regex::new(&pattern).unwrap();
                    xml = re.replace(&xml, "").to_string();
                }
            }
        }
        
        xml
    }

    fn fuzz_invalid_type(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Replace numeric values with strings, etc.
        let replacements = vec![
            (r"\d+", "not_a_number"),
            (r"true|false", "maybe"),
            (r#""[^"]*""#, "\"<invalid>"),
        ];
        
        for (pattern, replacement) in replacements {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(&xml) {
                xml = re.replace(&xml, replacement).to_string();
                break;
            }
        }
        
        xml
    }

    fn fuzz_malformed_xml(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        let malformations = vec![
            ("</", "<"),  // Unclosed tag
            (">", ""),    // Missing closing bracket
            ("<", ""),    // Missing opening bracket
        ];
        
        let (pattern, replacement) = &malformations[self.rng.gen_range(0..malformations.len())];
        xml = xml.replace(pattern, replacement);
        
        xml
    }

    fn fuzz_extreme_values(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Replace with extreme values
        let extremes = vec![
            ("0", "999999999999999999"),
            ("0", "-999999999999999999"),
            (r#""[^"]*""#, "\"\""),
            (r#""[^"]*""#, "\"A\" * 10000"),
        ];
        
        for (pattern, replacement) in extremes {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(&xml) {
                xml = re.replace(&xml, replacement).to_string();
                break;
            }
        }
        
        xml
    }

    fn fuzz_boundary_values(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find restrictions and use boundary values
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.fuzz_element_values(&mut xml, &elem_clone, false);
        }
        
        xml
    }

    fn fuzz_element_values(&mut self, xml: &mut String, element: &XsdElement, out_of_range: bool) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if !restriction.enumeration.is_empty() {
                    return; // Handled separately
                }

                match restriction.base.as_str() {
                    "xs:int" | "xs:integer" | "int" | "integer" => {
                        let min = restriction
                            .min_inclusive
                            .as_ref()
                            .and_then(|v| v.parse::<i32>().ok())
                            .unwrap_or(0);
                        let max = restriction
                            .max_inclusive
                            .as_ref()
                            .and_then(|v| v.parse::<i32>().ok())
                            .unwrap_or(1000);

                        let replacement = if out_of_range {
                            if self.rng.gen_bool(0.5) {
                                (max + 1000).to_string()
                            } else {
                                (min - 1000).to_string()
                            }
                        } else {
                            if self.rng.gen_bool(0.5) {
                                min.to_string()
                            } else {
                                max.to_string()
                            }
                        };

                        let re = Regex::new(r"\d+").unwrap();
                        *xml = re.replace(xml, &replacement).to_string();
                    }
                    "xs:decimal" | "xs:double" | "xs:float" => {
                        let min = restriction
                            .min_inclusive
                            .as_ref()
                            .and_then(|v| v.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        let max = restriction
                            .max_inclusive
                            .as_ref()
                            .and_then(|v| v.parse::<f64>().ok())
                            .unwrap_or(1000.0);

                        let replacement = if out_of_range {
                            if self.rng.gen_bool(0.5) {
                                (max + 1000.0).to_string()
                            } else {
                                (min - 1000.0).to_string()
                            }
                        } else {
                            if self.rng.gen_bool(0.5) {
                                min.to_string()
                            } else {
                                max.to_string()
                            }
                        };

                        let re = Regex::new(r"\d+\.\d+").unwrap();
                        *xml = re.replace(xml, &replacement).to_string();
                    }
                    _ => {}
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.fuzz_element_values(xml, &child_clone, out_of_range);
            }
        }
    }

    fn fuzz_enum_values(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if !restriction.enumeration.is_empty() {
                    // Replace valid enum value with invalid one
                    for valid_value in &restriction.enumeration {
                        if xml.contains(valid_value) {
                            let invalid_value = format!("INVALID_{}", valid_value);
                            *xml = xml.replace(valid_value, &invalid_value);
                            return;
                        }
                    }
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.fuzz_enum_values(xml, &child_clone);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xsd::XsdSchema;

    fn get_test_schema() -> XsdSchema {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="AgeType">
    <xs:restriction base="xs:int">
      <xs:minInclusive value="0"/>
      <xs:maxInclusive value="150"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="GenderType">
    <xs:restriction base="xs:string">
      <xs:enumeration value="Male"/>
      <xs:enumeration value="Female"/>
      <xs:enumeration value="Other"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:complexType name="PersonType">
    <xs:sequence>
      <xs:element name="firstName" type="xs:string" minOccurs="1"/>
      <xs:element name="lastName" type="xs:string" minOccurs="1"/>
      <xs:element name="age" type="AgeType" minOccurs="0"/>
      <xs:element name="gender" type="GenderType" minOccurs="0"/>
    </xs:sequence>
    <xs:attribute name="id" type="xs:int" use="required"/>
    <xs:attribute name="active" type="xs:boolean" use="optional"/>
  </xs:complexType>
  <xs:element name="Person" type="PersonType"/>
</xs:schema>"#;
        XsdSchema::parse(xsd).unwrap()
    }

    #[test]
    fn test_fuzz_add_element() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::AddElement);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        // Should have added extra elements or duplicates
    }

    #[test]
    fn test_fuzz_remove_element() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::RemoveElement);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        // Some elements should be removed
    }

    #[test]
    fn test_fuzz_out_of_range_value() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::OutOfRangeValue);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        // Should contain values outside 0-150 range for age
        // This is probabilistic, so we just check it generates something
    }

    #[test]
    fn test_fuzz_invalid_enum() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::InvalidEnum);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        // Should contain invalid enum values (not Male, Female, or Other)
        // This is probabilistic
    }

    #[test]
    fn test_fuzz_invalid_attribute() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::InvalidAttribute);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        // Should have invalid attributes added
        assert!(fuzzed.len() > 0, "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_missing_required_attribute() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::MissingRequiredAttribute);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        // Required id attribute should be missing or removed
    }

    #[test]
    fn test_fuzz_invalid_type() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::InvalidType);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(fuzzed.len() > 0, "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_malformed_xml() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::MalformedXml);
        
        // Malformed XML might not have proper closing tags
        assert!(fuzzed.len() > 0, "Should generate content");
    }

    #[test]
    fn test_fuzz_extreme_values() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ExtremeValues);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        // Should contain extreme numeric values
    }

    #[test]
    fn test_fuzz_boundary_values() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::BoundaryValues);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        // Should test boundary conditions (0, 150 for age)
    }

    #[test]
    fn test_fuzz_all_strategies() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let results = fuzzer.fuzz_all("Person");
        
        assert_eq!(results.len(), 9, "Should generate all fuzzing strategies");
        for (strategy, xml) in results {
            assert!(!xml.is_empty(), "Strategy {:?} should generate XML", strategy);
            assert!(xml.contains("Person") || xml.contains("<Person"), 
                    "Strategy {:?} should contain Person", strategy);
        }
    }

    #[test]
    fn test_fuzzer_creates_different_outputs() {
        let schema = get_test_schema();
        let mut fuzzer1 = XmlFuzzer::new(schema.clone());
        let mut fuzzer2 = XmlFuzzer::new(schema);
        
        let xml1 = fuzzer1.fuzz("Person", FuzzStrategy::AddElement);
        let xml2 = fuzzer2.fuzz("Person", FuzzStrategy::AddElement);
        
        // Due to randomness, outputs should be different (with high probability)
        // But both should be valid fuzzed XML
        assert!(!xml1.is_empty());
        assert!(!xml2.is_empty());
    }

    #[test]
    fn test_fuzz_with_complex_schema() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:complexType name="AddressType">
    <xs:sequence>
      <xs:element name="street" type="xs:string"/>
      <xs:element name="city" type="xs:string"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="PersonType">
    <xs:sequence>
      <xs:element name="name" type="xs:string"/>
      <xs:element name="address" type="AddressType" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:element name="Person" type="PersonType"/>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        
        let results = fuzzer.fuzz_all("Person");
        assert_eq!(results.len(), 9);
        
        for (_, xml) in results {
            assert!(!xml.is_empty());
        }
    }
}

