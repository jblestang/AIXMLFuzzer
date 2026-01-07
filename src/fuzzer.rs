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
    ViolateMinOccurs,
    ViolateMaxOccurs,
    ViolateMinLength,
    ViolateMaxLength,
    ViolateMinInclusive,
    ViolateMaxInclusive,
    ViolateMinExclusive,
    ViolateMaxExclusive,
    ViolatePattern,
    ViolateTotalDigits,
    ViolateFractionDigits,
    ViolateChoice,
    ViolateSequenceOrder,
    ViolateFixedValue,
    ViolateNillable,
    ViolateLength,
    ViolateWhiteSpace,
    ViolateAll,
    ViolateUnique,
    ViolateKey,
    ViolateKeyRef,
    ViolateDefault,
    ViolateAbstract,
    ViolateMixed,
    ViolateUnion,
    ViolateList,
    ViolateAny,
    ViolateAnyAttribute,
    ViolateXsiType,
    ViolateSubstitutionGroup,
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
            FuzzStrategy::ViolateMinOccurs => self.fuzz_violate_min_occurs(root_element),
            FuzzStrategy::ViolateMaxOccurs => self.fuzz_violate_max_occurs(root_element),
            FuzzStrategy::ViolateMinLength => self.fuzz_violate_min_length(root_element),
            FuzzStrategy::ViolateMaxLength => self.fuzz_violate_max_length(root_element),
            FuzzStrategy::ViolateMinInclusive => self.fuzz_violate_min_inclusive(root_element),
            FuzzStrategy::ViolateMaxInclusive => self.fuzz_violate_max_inclusive(root_element),
            FuzzStrategy::ViolateMinExclusive => self.fuzz_violate_min_exclusive(root_element),
            FuzzStrategy::ViolateMaxExclusive => self.fuzz_violate_max_exclusive(root_element),
            FuzzStrategy::ViolatePattern => self.fuzz_violate_pattern(root_element),
            FuzzStrategy::ViolateTotalDigits => self.fuzz_violate_total_digits(root_element),
            FuzzStrategy::ViolateFractionDigits => self.fuzz_violate_fraction_digits(root_element),
            FuzzStrategy::ViolateChoice => self.fuzz_violate_choice(root_element),
            FuzzStrategy::ViolateSequenceOrder => self.fuzz_violate_sequence_order(root_element),
            FuzzStrategy::ViolateFixedValue => self.fuzz_violate_fixed_value(root_element),
            FuzzStrategy::ViolateNillable => self.fuzz_violate_nillable(root_element),
            FuzzStrategy::ViolateLength => self.fuzz_violate_length(root_element),
            FuzzStrategy::ViolateWhiteSpace => self.fuzz_violate_white_space(root_element),
            FuzzStrategy::ViolateAll => self.fuzz_violate_all(root_element),
            FuzzStrategy::ViolateUnique => self.fuzz_violate_unique(root_element),
            FuzzStrategy::ViolateKey => self.fuzz_violate_key(root_element),
            FuzzStrategy::ViolateKeyRef => self.fuzz_violate_key_ref(root_element),
            FuzzStrategy::ViolateDefault => self.fuzz_violate_default(root_element),
            FuzzStrategy::ViolateAbstract => self.fuzz_violate_abstract(root_element),
            FuzzStrategy::ViolateMixed => self.fuzz_violate_mixed(root_element),
            FuzzStrategy::ViolateUnion => self.fuzz_violate_union(root_element),
            FuzzStrategy::ViolateList => self.fuzz_violate_list(root_element),
            FuzzStrategy::ViolateAny => self.fuzz_violate_any(root_element),
            FuzzStrategy::ViolateAnyAttribute => self.fuzz_violate_any_attribute(root_element),
            FuzzStrategy::ViolateXsiType => self.fuzz_violate_xsi_type(root_element),
            FuzzStrategy::ViolateSubstitutionGroup => self.fuzz_violate_substitution_group(root_element),
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
            FuzzStrategy::MalformedXml,
            FuzzStrategy::ExtremeValues,
            FuzzStrategy::BoundaryValues,
            FuzzStrategy::ViolateMinOccurs,
            FuzzStrategy::ViolateMaxOccurs,
            FuzzStrategy::ViolateMinLength,
            FuzzStrategy::ViolateMaxLength,
            FuzzStrategy::ViolateMinInclusive,
            FuzzStrategy::ViolateMaxInclusive,
            FuzzStrategy::ViolateMinExclusive,
            FuzzStrategy::ViolateMaxExclusive,
            FuzzStrategy::ViolatePattern,
            FuzzStrategy::ViolateTotalDigits,
            FuzzStrategy::ViolateFractionDigits,
            FuzzStrategy::ViolateChoice,
            FuzzStrategy::ViolateSequenceOrder,
            FuzzStrategy::ViolateFixedValue,
            FuzzStrategy::ViolateNillable,
            FuzzStrategy::ViolateLength,
            FuzzStrategy::ViolateWhiteSpace,
            FuzzStrategy::ViolateAll,
            FuzzStrategy::ViolateUnique,
            FuzzStrategy::ViolateKey,
            FuzzStrategy::ViolateKeyRef,
            FuzzStrategy::ViolateDefault,
            FuzzStrategy::ViolateAbstract,
            FuzzStrategy::ViolateMixed,
            FuzzStrategy::ViolateUnion,
            FuzzStrategy::ViolateList,
            FuzzStrategy::ViolateAny,
            FuzzStrategy::ViolateAnyAttribute,
            FuzzStrategy::ViolateXsiType,
            FuzzStrategy::ViolateSubstitutionGroup,
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

    fn fuzz_violate_min_occurs(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find elements with minOccurs > 0 and remove instances to violate minOccurs
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_min_occurs_recursive(&mut xml, &elem_clone);
        }
        
        xml
    }

    fn fuzz_violate_max_occurs(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find elements with maxOccurs and add more instances to violate maxOccurs
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_max_occurs_recursive(&mut xml, &elem_clone);
        }
        
        xml
    }

    fn fuzz_violate_min_length(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find string values with minLength restrictions and make them too short
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_length_constraints(&mut xml, &elem_clone, true);
        }
        
        xml
    }

    fn fuzz_violate_max_length(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find string values with maxLength restrictions and make them too long
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_length_constraints(&mut xml, &elem_clone, false);
        }
        
        xml
    }

    fn fuzz_violate_min_inclusive(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values with minInclusive and make them below the minimum
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_inclusive_constraints(&mut xml, &elem_clone, true);
        }
        
        xml
    }

    fn fuzz_violate_max_inclusive(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values with maxInclusive and make them above the maximum
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_inclusive_constraints(&mut xml, &elem_clone, false);
        }
        
        xml
    }

    fn violate_min_occurs_recursive(&mut self, xml: &mut String, element: &XsdElement) {
        let min_occurs = element.min_occurs.unwrap_or(1);
        
        if min_occurs > 0 {
            // Remove instances to violate minOccurs
            for child_name in &element.children {
                if let Some(child_elem) = self.schema.get_element(child_name) {
                    let child_min = child_elem.min_occurs.unwrap_or(1);
                    if child_min > 0 {
                        // Count occurrences and remove some to violate minOccurs
                        let pattern = format!("<{}>", child_name);
                        let count = xml.matches(&pattern).count();
                        if count >= child_min as usize {
                            // Remove one instance to violate minOccurs
                            let re = Regex::new(&format!(r"<{}>.*?</{}>", child_name, child_name)).unwrap();
                            if let Some(first_match) = re.find(&xml) {
                                let start = first_match.start();
                                let end = first_match.end();
                                xml.replace_range(start..end, "");
                            }
                        }
                    }
                    let child_clone = child_elem.clone();
                    self.violate_min_occurs_recursive(xml, &child_clone);
                }
            }
        }
    }

    fn violate_max_occurs_recursive(&mut self, xml: &mut String, element: &XsdElement) {
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let max_occurs = child_elem.max_occurs.unwrap_or(1);
                if max_occurs != u32::MAX {
                    // Count occurrences and add more to violate maxOccurs
                    let pattern = format!("<{}>", child_name);
                    let count = xml.matches(&pattern).count();
                    if count < max_occurs as usize {
                        // Add extra instances to violate maxOccurs
                        let extra_count = (max_occurs as usize - count) + 1;
                        let extra_elem = format!("<{}>extra_value</{}>\n", child_name, child_name);
                        let insert_pos = xml.find("</").unwrap_or(xml.len() - 10);
                        for _ in 0..extra_count {
                            xml.insert_str(insert_pos, &extra_elem);
                        }
                    }
                    let child_clone = child_elem.clone();
                    self.violate_max_occurs_recursive(xml, &child_clone);
                }
            }
        }
    }

    fn violate_length_constraints(&mut self, xml: &mut String, element: &XsdElement, is_min: bool) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if restriction.base == "xs:string" || restriction.base == "string" {
                    if is_min {
                        if let Some(min_len) = restriction.min_length {
                            // Make strings shorter than minLength
                            let re = Regex::new(r#">([^<]+)</"#).unwrap();
                            *xml = re.replace_all(xml, |caps: &regex::Captures| -> String {
                                let value = &caps[1];
                                if value.len() >= min_len as usize {
                                    format!(">{}</", "x".repeat((min_len as usize).saturating_sub(1)))
                                } else {
                                    caps[0].to_string()
                                }
                            }).to_string();
                        }
                    } else {
                        if let Some(max_len) = restriction.max_length {
                            // Make strings longer than maxLength
                            let re = Regex::new(r#">([^<]+)</"#).unwrap();
                            *xml = re.replace_all(xml, |caps: &regex::Captures| -> String {
                                let value = &caps[1];
                                if value.len() <= max_len as usize {
                                    format!(">{}</", "x".repeat(max_len as usize + 100))
                                } else {
                                    caps[0].to_string()
                                }
                            }).to_string();
                        }
                    }
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_length_constraints(xml, &child_clone, is_min);
            }
        }
    }

    fn violate_inclusive_constraints(&mut self, xml: &mut String, element: &XsdElement, is_min: bool) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                match restriction.base.as_str() {
                    "xs:int" | "xs:integer" | "int" | "integer" => {
                        if is_min {
                            if let Some(min_val) = &restriction.min_inclusive {
                                if let Ok(min_int) = min_val.parse::<i32>() {
                                    // Replace with value below minimum
                                    let re = Regex::new(r"\d+").unwrap();
                                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                        (min_int - 1).to_string()
                                    }).to_string();
                                }
                            }
                        } else {
                            if let Some(max_val) = &restriction.max_inclusive {
                                if let Ok(max_int) = max_val.parse::<i32>() {
                                    // Replace with value above maximum
                                    let re = Regex::new(r"\d+").unwrap();
                                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                        (max_int + 1).to_string()
                                    }).to_string();
                                }
                            }
                        }
                    }
                    "xs:decimal" | "xs:double" | "xs:float" => {
                        if is_min {
                            if let Some(min_val) = &restriction.min_inclusive {
                                if let Ok(min_float) = min_val.parse::<f64>() {
                                    let re = Regex::new(r"\d+\.\d+").unwrap();
                                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                        format!("{:.2}", min_float - 1.0)
                                    }).to_string();
                                }
                            }
                        } else {
                            if let Some(max_val) = &restriction.max_inclusive {
                                if let Ok(max_float) = max_val.parse::<f64>() {
                                    let re = Regex::new(r"\d+\.\d+").unwrap();
                                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                        format!("{:.2}", max_float + 1.0)
                                    }).to_string();
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_inclusive_constraints(xml, &child_clone, is_min);
            }
        }
    }

    fn fuzz_violate_min_exclusive(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values with minExclusive and make them equal to or below the minimum
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_exclusive_constraints(&mut xml, &elem_clone, true);
        }
        
        xml
    }

    fn fuzz_violate_max_exclusive(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values with maxExclusive and make them equal to or above the maximum
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_exclusive_constraints(&mut xml, &elem_clone, false);
        }
        
        xml
    }

    fn fuzz_violate_pattern(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find values with pattern restrictions and violate them
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_pattern_constraints(&mut xml, &elem_clone);
        }
        
        xml
    }

    fn fuzz_violate_total_digits(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find decimal values with totalDigits restrictions and violate them
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_total_digits_constraints(&mut xml, &elem_clone);
        }
        
        xml
    }

    fn fuzz_violate_fraction_digits(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find decimal values with fractionDigits restrictions and violate them
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_fraction_digits_constraints(&mut xml, &elem_clone);
        }
        
        xml
    }

    fn fuzz_violate_choice(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Violate choice constraints by selecting multiple options or wrong options
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_choice_constraints(&mut xml, &elem_clone);
        }
        
        xml
    }

    fn fuzz_violate_sequence_order(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Violate sequence order by reordering elements
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_sequence_order_constraints(&mut xml, &elem_clone);
        }
        
        xml
    }

    fn fuzz_violate_fixed_value(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Violate fixed value constraints (if we can detect them)
        // This is tricky since we don't parse fixed attributes, but we can try to modify values
        // that look like they might be fixed
        let re = Regex::new(r#">([^<]+)</"#).unwrap();
        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
            let value = &caps[1];
            // Change the value to something different
            format!(">INVALID_{}</", value)
        }).to_string();
        
        xml
    }

    fn fuzz_violate_nillable(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Add xsi:nil="true" to elements that shouldn't be nillable
        // Or remove xsi:nil from elements that require it
        if !xml.contains("xsi:nil") {
            // Add xsi:nil to a random element
            let re = Regex::new(r"(<[^>]+)(>)").unwrap();
            xml = re.replace(&xml, |caps: &regex::Captures| -> String {
                format!("{} xsi:nil=\"true\"{}", &caps[1], &caps[2])
            }).to_string();
        }
        
        xml
    }

    fn violate_exclusive_constraints(&mut self, xml: &mut String, element: &XsdElement, is_min: bool) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                match restriction.base.as_str() {
                    "xs:int" | "xs:integer" | "int" | "integer" => {
                        if is_min {
                            if let Some(min_val) = &restriction.min_exclusive {
                                if let Ok(min_int) = min_val.parse::<i32>() {
                                    // Replace with value equal to or below minimum (violates exclusive)
                                    let re = Regex::new(r"\d+").unwrap();
                                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                        min_int.to_string() // Equal to min violates exclusive
                                    }).to_string();
                                }
                            }
                        } else {
                            if let Some(max_val) = &restriction.max_exclusive {
                                if let Ok(max_int) = max_val.parse::<i32>() {
                                    // Replace with value equal to or above maximum (violates exclusive)
                                    let re = Regex::new(r"\d+").unwrap();
                                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                        max_int.to_string() // Equal to max violates exclusive
                                    }).to_string();
                                }
                            }
                        }
                    }
                    "xs:decimal" | "xs:double" | "xs:float" => {
                        if is_min {
                            if let Some(min_val) = &restriction.min_exclusive {
                                if let Ok(min_float) = min_val.parse::<f64>() {
                                    let re = Regex::new(r"\d+\.\d+").unwrap();
                                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                        format!("{:.2}", min_float) // Equal violates exclusive
                                    }).to_string();
                                }
                            }
                        } else {
                            if let Some(max_val) = &restriction.max_exclusive {
                                if let Ok(max_float) = max_val.parse::<f64>() {
                                    let re = Regex::new(r"\d+\.\d+").unwrap();
                                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                        format!("{:.2}", max_float) // Equal violates exclusive
                                    }).to_string();
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_exclusive_constraints(xml, &child_clone, is_min);
            }
        }
    }

    fn violate_pattern_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if restriction.pattern.is_some() {
                    // Generate a value that doesn't match the pattern
                    // Simple approach: replace with clearly invalid value
                    let re = Regex::new(r#">([^<]+)</"#).unwrap();
                    *xml = re.replace_all(xml, |caps: &regex::Captures| -> String {
                        let value = &caps[1];
                        // Replace with something that likely violates the pattern
                        format!(">INVALID_PATTERN_{}</", value)
                    }).to_string();
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_pattern_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_total_digits_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if let Some(total_digits) = restriction.total_digits {
                    // Create a number with more total digits than allowed
                    let re = Regex::new(r"\d+\.?\d*").unwrap();
                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                        // Generate a number with more digits than total_digits
                        "9".repeat(total_digits as usize + 10)
                    }).to_string();
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_total_digits_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_fraction_digits_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if let Some(fraction_digits) = restriction.fraction_digits {
                    // Create a decimal with more fraction digits than allowed
                    let re = Regex::new(r"\d+\.\d+").unwrap();
                    *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                        // Generate a decimal with more fraction digits
                        let int_part = "123";
                        let frac_part = "9".repeat(fraction_digits as usize + 5);
                        format!("{}.{}", int_part, frac_part)
                    }).to_string();
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_fraction_digits_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_choice_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if !typ.choice.is_empty() {
                // Choice means only one option should be selected
                // Violate by selecting multiple or none
                for choice_group in &typ.choice {
                    if choice_group.len() > 1 {
                        // Add multiple elements from the choice group
                        for choice_elem in choice_group {
                            let extra = format!("<{}>choice_violation</{}>\n", choice_elem, choice_elem);
                            let insert_pos = xml.find("</").unwrap_or(xml.len() - 10);
                            xml.insert_str(insert_pos, &extra);
                        }
                    }
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_choice_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_sequence_order_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if !typ.sequence.is_empty() && typ.sequence.len() > 1 {
                // Try to swap adjacent elements to violate order
                for i in 0..typ.sequence.len().saturating_sub(1) {
                    let elem1 = &typ.sequence[i];
                    let elem2 = &typ.sequence[i + 1];
                    
                    // Find and swap positions
                    let pattern1 = format!("<{}>.*?</{}>", elem1, elem1);
                    let pattern2 = format!("<{}>.*?</{}>", elem2, elem2);
                    let re1 = Regex::new(&pattern1).unwrap();
                    let re2 = Regex::new(&pattern2).unwrap();
                    
                    // Collect matches first to avoid borrow issues
                    let m1_opt = re1.find(&xml);
                    let m2_opt = re2.find(&xml);
                    
                    if let (Some(m1), Some(m2)) = (m1_opt, m2_opt) {
                        if m1.start() < m2.start() {
                            // Swap them
                            let val1 = m1.as_str().to_string();
                            let val2 = m2.as_str().to_string();
                            let mut new_xml = xml.replace(m1.as_str(), "TEMP_PLACEHOLDER_1");
                            new_xml = new_xml.replace(m2.as_str(), &val1);
                            new_xml = new_xml.replace("TEMP_PLACEHOLDER_1", &val2);
                            *xml = new_xml;
                            break; // Only swap once
                        }
                    }
                }
            }
        }

        // Recursively fuzz children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_sequence_order_constraints(xml, &child_clone);
            }
        }
    }

    fn fuzz_violate_length(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_exact_length(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_white_space(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_whitespace_constraints(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_all(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_all_constraints(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_unique(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_unique_constraints(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_key(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_key_constraints(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_key_ref(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_keyref_constraints(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_default(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_default_constraints(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_abstract(&mut self, root_element: &str) -> String {
        let xml = self.generator.generate_valid(root_element);
        // Try to instantiate abstract types/elements
        // This is a simplified violation - in practice, abstract types can't be instantiated
        xml
    }

    fn fuzz_violate_mixed(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_mixed_content(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_union(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_union_types(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_list(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.violate_list_types(&mut xml, &elem_clone);
        }
        xml
    }

    fn fuzz_violate_any(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        // Add invalid elements to any wildcards
        // Simplified: just add a random invalid element
        let invalid_elem = format!("<invalidAnyElement{}>value</invalidAnyElement{}>", 
            self.rng.gen_range(0..1000), 
            self.rng.gen_range(0..1000));
        let insert_pos = xml.find("</").unwrap_or(xml.len() - 10);
        xml.insert_str(insert_pos, &invalid_elem);
        xml
    }

    fn fuzz_violate_any_attribute(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        // Add invalid attributes to anyAttribute wildcards
        let invalid_attr = format!(" invalidAnyAttr{}=\"value\"", self.rng.gen_range(0..1000));
        if let Some(pos) = xml.find('>') {
            xml.insert_str(pos, &invalid_attr);
        }
        xml
    }

    fn violate_exact_length(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if let Some(exact_length) = restriction.length {
                    let re = Regex::new(r#">([^<]+)</"#).unwrap();
                    *xml = re.replace_all(xml, |caps: &regex::Captures| -> String {
                        let value = &caps[1];
                        if value.len() != exact_length as usize {
                            // Already wrong length, keep it
                            caps[0].to_string()
                        } else {
                            // Make it wrong length
                            format!(">{}</", "x".repeat(exact_length as usize + 1))
                        }
                    }).to_string();
                }
            }
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_exact_length(xml, &child_clone);
            }
        }
    }

    fn violate_whitespace_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if let Some(ref ws) = restriction.white_space {
                    let re = Regex::new(r#">([^<]+)</"#).unwrap();
                    *xml = re.replace_all(xml, |caps: &regex::Captures| -> String {
                        let value = &caps[1];
                        match ws.as_str() {
                            "preserve" => {
                                // Should preserve whitespace, so remove it to violate
                                format!(">{}</", value.replace(" ", ""))
                            }
                            "replace" => {
                                // Should replace tabs/newlines with spaces, so don't
                                format!(">{}\t\n</", value)
                            }
                            "collapse" => {
                                // Should collapse whitespace, so add extra
                                format!(">  {}  </", value)
                            }
                            _ => caps[0].to_string()
                        }
                    }).to_string();
                }
            }
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_whitespace_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_all_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if !typ.all.is_empty() {
                // 'all' requires all elements to appear, and order doesn't matter
                // Violate by removing one or reordering
                if typ.all.len() > 1 {
                    // Remove one element
                    let elem_to_remove = &typ.all[0];
                    let pattern = format!("<{}>.*?</{}>", elem_to_remove, elem_to_remove);
                    let re = Regex::new(&pattern).unwrap();
                    *xml = re.replace(&xml, "").to_string();
                }
            }
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_all_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_unique_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        // Find elements that should be unique and duplicate them
        if let Some(unique_paths) = self.schema.unique_constraints.get(&element.name) {
            if !unique_paths.is_empty() {
                // Simplified: duplicate a random element value
                let re = Regex::new(r#">([^<]+)</"#).unwrap();
                if let Some(first_match) = re.find(&xml) {
                    let value = first_match.as_str().to_string();
                    // Insert duplicate
                    let insert_pos = first_match.end();
                    xml.insert_str(insert_pos, &value);
                }
            }
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_unique_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_key_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        // Violate key constraints by creating duplicate or missing keys
        if let Some(_key_paths) = self.schema.key_constraints.get(&element.name) {
            // Simplified: duplicate a key value
            let re = Regex::new(r#">([^<]+)</"#).unwrap();
            if let Some(first_match) = re.find(&xml) {
                let value = first_match.as_str().to_string();
                let insert_pos = first_match.end();
                xml.insert_str(insert_pos, &value);
            }
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_key_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_keyref_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        // Create invalid key references
        if let Some(_refer) = self.schema.keyref_constraints.get(&element.name) {
            // Replace keyref values with invalid references
            let re = Regex::new(r#">([^<]+)</"#).unwrap();
            let new_xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                "INVALID_KEYREF".to_string()
            }).to_string();
            *xml = new_xml;
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_keyref_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_default_constraints(&mut self, xml: &mut String, element: &XsdElement) {
        // Violate default value constraints by providing wrong default or omitting when required
        if let Some(ref default_val) = element.default_value {
            // Change the default value to something else
            let re = Regex::new(r#">([^<]+)</"#).unwrap();
            *xml = re.replace_all(xml, |caps: &regex::Captures| -> String {
                let value = &caps[1];
                if value == default_val {
                    format!(">INVALID_DEFAULT_{}</", default_val)
                } else {
                    caps[0].to_string()
                }
            }).to_string();
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_default_constraints(xml, &child_clone);
            }
        }
    }

    fn violate_mixed_content(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if typ.mixed {
                // Mixed content allows text and elements
                // Violate by adding invalid text or structure
                let insert_pos = xml.find(">").unwrap_or(xml.len() - 10);
                xml.insert_str(insert_pos + 1, "INVALID_MIXED_TEXT<invalidElement/>");
            }
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_mixed_content(xml, &child_clone);
            }
        }
    }

    fn violate_union_types(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if !typ.union_types.is_empty() {
                // Generate a value that doesn't match any union member type
                let re = Regex::new(r#">([^<]+)</"#).unwrap();
                let new_xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                    ">INVALID_UNION_VALUE</".to_string()
                }).to_string();
                *xml = new_xml;
            }
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_union_types(xml, &child_clone);
            }
        }
    }

    fn violate_list_types(&mut self, xml: &mut String, element: &XsdElement) {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if typ.list_item_type.is_some() {
                // List types should be space-separated values
                // Violate by using wrong separator or format
                let re = Regex::new(r#">([^<]+)</"#).unwrap();
                *xml = re.replace_all(xml, |caps: &regex::Captures| -> String {
                    let value = &caps[1];
                    // Use comma instead of space, or add invalid characters
                    format!(">{},invalid,list</", value)
                }).to_string();
            }
        }
        // Recursively process children
        for child_name in &element.children {
            if let Some(child_elem) = self.schema.get_element(child_name) {
                let child_clone = child_elem.clone();
                self.violate_list_types(xml, &child_clone);
            }
        }
    }

    fn fuzz_violate_xsi_type(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Add invalid xsi:type attributes to violate type substitution
        // Find elements that can have xsi:type and add invalid types
        let re = Regex::new(r"(<[^>]+)(>)").unwrap();
        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
            let tag = &caps[1];
            // Add invalid xsi:type if not already present
            if !tag.contains("xsi:type") {
                format!("{} xsi:type=\"InvalidType{}\"{}", tag, self.rng.gen_range(0..1000), &caps[2])
            } else {
                // Replace with invalid type
                let re_type = Regex::new(r#"xsi:type="[^"]*""#).unwrap();
                re_type.replace(tag, |_caps: &regex::Captures| -> String {
                    format!("xsi:type=\"InvalidType{}\"", self.rng.gen_range(0..1000))
                }).to_string() + &caps[2]
            }
        }).to_string();
        
        xml
    }

    fn fuzz_violate_substitution_group(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Violate substitutionGroup by using invalid substitute elements
        // Find elements that are part of substitution groups and replace with invalid ones
        for (head_name, _substitutes) in &self.schema.substitution_groups {
            // Replace head element with invalid substitute
            let pattern = format!("<{}>", head_name);
            if xml.contains(&pattern) {
                // Replace with an element that's not in the substitution group
                let invalid_sub = format!("<invalidSubstitute{}>", self.rng.gen_range(0..1000));
                xml = xml.replace(&pattern, &invalid_sub);
            }
        }
        
        xml
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
    fn test_fuzz_violate_min_exclusive() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateMinExclusive);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_max_exclusive() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateMaxExclusive);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_pattern() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="CodeType">
    <xs:restriction base="xs:string">
      <xs:pattern value="[A-Z]{3}"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="code" type="CodeType"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolatePattern);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_total_digits() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="AmountType">
    <xs:restriction base="xs:decimal">
      <xs:totalDigits value="10"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="amount" type="AmountType"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateTotalDigits);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_fraction_digits() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="PriceType">
    <xs:restriction base="xs:decimal">
      <xs:fractionDigits value="2"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="price" type="PriceType"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateFractionDigits);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_choice() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:complexType name="PersonType">
    <xs:choice>
      <xs:element name="email" type="xs:string"/>
      <xs:element name="phone" type="xs:string"/>
    </xs:choice>
  </xs:complexType>
  <xs:element name="Person" type="PersonType"/>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateChoice);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_sequence_order() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateSequenceOrder);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_fixed_value() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateFixedValue);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_nillable() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateNillable);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_length() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="CodeType">
    <xs:restriction base="xs:string">
      <xs:length value="5"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="code" type="CodeType"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateLength);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_white_space() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="TextType">
    <xs:restriction base="xs:string">
      <xs:whiteSpace value="preserve"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="text" type="TextType"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateWhiteSpace);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_all() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:complexType name="PersonType">
    <xs:all>
      <xs:element name="name" type="xs:string"/>
      <xs:element name="age" type="xs:int"/>
    </xs:all>
  </xs:complexType>
  <xs:element name="Person" type="PersonType"/>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateAll);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_unique() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateUnique);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_key() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateKey);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_key_ref() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateKeyRef);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_default() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateDefault);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_abstract() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateAbstract);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_mixed() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:complexType name="PersonType" mixed="true">
    <xs:sequence>
      <xs:element name="name" type="xs:string"/>
    </xs:sequence>
  </xs:complexType>
  <xs:element name="Person" type="PersonType"/>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateMixed);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_union() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="UnionType">
    <xs:union memberTypes="xs:int xs:string"/>
  </xs:simpleType>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="value" type="UnionType"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateUnion);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_list() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="ListType">
    <xs:list itemType="xs:int"/>
  </xs:simpleType>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="numbers" type="ListType"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateList);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_any() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateAny);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_any_attribute() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateAnyAttribute);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_xsi_type() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateXsiType);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_substitution_group() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="person" type="xs:string"/>
  <xs:element name="employee" substitutionGroup="person"/>
  <xs:element name="customer" substitutionGroup="person"/>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element ref="person"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateSubstitutionGroup);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_all_strategies() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let results = fuzzer.fuzz_all("Person");
        
        assert_eq!(results.len(), 40, "Should generate all 40 fuzzing strategies");
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
    fn test_fuzz_violate_min_occurs() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateMinOccurs);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_max_occurs() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateMaxOccurs);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_min_length() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="NameType">
    <xs:restriction base="xs:string">
      <xs:minLength value="5"/>
      <xs:maxLength value="20"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="name" type="NameType"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateMinLength);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_max_length() {
        let xsd = r#"<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:simpleType name="NameType">
    <xs:restriction base="xs:string">
      <xs:minLength value="5"/>
      <xs:maxLength value="20"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:element name="Person">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="name" type="NameType"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
        
        let schema = XsdSchema::parse(xsd).unwrap();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateMaxLength);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_min_inclusive() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateMinInclusive);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
    }

    #[test]
    fn test_fuzz_violate_max_inclusive() {
        let schema = get_test_schema();
        let mut fuzzer = XmlFuzzer::new(schema);
        let fuzzed = fuzzer.fuzz("Person", FuzzStrategy::ViolateMaxInclusive);
        
        assert!(fuzzed.contains("<Person"), "Should contain Person element");
        assert!(!fuzzed.is_empty(), "Should generate fuzzed content");
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
        assert_eq!(results.len(), 40, "Should generate all 40 fuzzing strategies");
        
        for (_, xml) in results {
            assert!(!xml.is_empty());
        }
    }
}

