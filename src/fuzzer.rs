//! XML Fuzzer
//! 
//! Implements various fuzzing strategies to generate invalid XML documents
//! that violate XSD schema constraints. Used for testing XML parsers and validators.

use crate::xsd::*;
use crate::xml_generator::XmlGenerator;
use rand::Rng;
use regex::Regex;

/// Enumeration of all available fuzzing strategies
/// Each strategy targets a specific type of XSD constraint violation
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

/// Represents a specific constraint violation in the schema
/// Used for sequential generation of all violations
#[derive(Debug, Clone)]
pub struct ConstraintViolation {
    /// Path to the element where violation occurs (e.g., "Person/age")
    pub element_path: String,
    /// Type of constraint being violated
    pub constraint_type: String,
    /// Strategy to use for this violation
    pub strategy: FuzzStrategy,
    /// Description of the violation
    pub description: String,
}

/// Main fuzzer struct that applies fuzzing strategies to XML generation
/// Uses a valid XML generator as a base and then applies mutations
pub struct XmlFuzzer {
    /// The parsed XSD schema
    schema: XsdSchema,
    /// XML generator for creating valid base XML
    generator: XmlGenerator,
    /// Random number generator for mutations
    rng: rand::rngs::ThreadRng,
    /// Flag to stop after first violation
    stop_after_first: bool,
}

impl XmlFuzzer {
    /// Create a new fuzzer with the given schema
    pub fn new(schema: XsdSchema) -> Self {
        let generator = XmlGenerator::new(schema.clone());
        Self {
            schema,
            generator,
            rng: rand::thread_rng(),
            stop_after_first: false,
        }
    }

    /// Create a new fuzzer that stops after first violation
    pub fn new_single_violation(schema: XsdSchema) -> Self {
        let generator = XmlGenerator::new(schema.clone());
        Self {
            schema,
            generator,
            rng: rand::thread_rng(),
            stop_after_first: true,
        }
    }

    /// Apply a fuzzing strategy to generate invalid XML
    /// Starts with valid XML and applies mutations based on the strategy
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

    /// Discover all constraint violations in the schema
    /// Returns a list of all violations that can be generated
    pub fn discover_all_violations(&self, root_element: &str) -> Vec<ConstraintViolation> {
        let mut violations = Vec::new();
        
        // Helper to recursively discover violations in elements
        fn discover_in_element(
            schema: &XsdSchema,
            element: &XsdElement,
            path: &str,
            violations: &mut Vec<ConstraintViolation>,
        ) {
            let current_path = if path.is_empty() {
                element.name.clone()
            } else {
                format!("{}/{}", path, element.name)
            };

            // Debug: Check if we're processing the right element
            // For elements defined in complex types, we need to check the type's restrictions

            // Check minOccurs constraint
            if element.min_occurs.is_some() && element.min_occurs.unwrap() > 0 {
                violations.push(ConstraintViolation {
                    element_path: current_path.clone(),
                    constraint_type: "minOccurs".to_string(),
                    strategy: FuzzStrategy::ViolateMinOccurs,
                    description: format!("Element {} has minOccurs={}", current_path, element.min_occurs.unwrap()),
                });
            }

            // Check maxOccurs constraint
            if element.max_occurs.is_some() {
                let max_occurs_str = if element.max_occurs.unwrap() == u32::MAX {
                    "unbounded".to_string()
                } else {
                    element.max_occurs.unwrap().to_string()
                };
                violations.push(ConstraintViolation {
                    element_path: current_path.clone(),
                    constraint_type: "maxOccurs".to_string(),
                    strategy: FuzzStrategy::ViolateMaxOccurs,
                    description: format!("Element {} has maxOccurs={}", current_path, max_occurs_str),
                });
            }

            // Check attributes
            for attr in &element.attributes {
                if attr.required {
                    violations.push(ConstraintViolation {
                        element_path: current_path.clone(),
                        constraint_type: "required_attribute".to_string(),
                        strategy: FuzzStrategy::MissingRequiredAttribute,
                        description: format!("Attribute {} is required on {}", attr.name, current_path),
                    });
                }
                if attr.default_value.is_some() {
                    violations.push(ConstraintViolation {
                        element_path: current_path.clone(),
                        constraint_type: "default_attribute".to_string(),
                        strategy: FuzzStrategy::ViolateDefault,
                        description: format!("Attribute {} has default value on {}", attr.name, current_path),
                    });
                }
            }

            // Check element type constraints
            // Try to get type - first try with full name, then without namespace prefix
            let type_name_full = &element.element_type;
            let type_name_short = element.element_type.split(':').last().unwrap_or(&element.element_type);
            
            // Try both full name and short name to handle namespace prefixes
            let typ = schema.get_type(type_name_full)
                .or_else(|| schema.get_type(type_name_short));
            
            if let Some(typ) = typ {
                if let Some(ref restriction) = typ.restriction {
                    // Check enumeration
                    if !restriction.enumeration.is_empty() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "enumeration".to_string(),
                            strategy: FuzzStrategy::InvalidEnum,
                            description: format!("Element {} has enumeration constraint", current_path),
                        });
                    }

                    // Check minLength
                    if restriction.min_length.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "minLength".to_string(),
                            strategy: FuzzStrategy::ViolateMinLength,
                            description: format!("Element {} has minLength={}", current_path, restriction.min_length.unwrap()),
                        });
                    }

                    // Check maxLength
                    if restriction.max_length.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "maxLength".to_string(),
                            strategy: FuzzStrategy::ViolateMaxLength,
                            description: format!("Element {} has maxLength={}", current_path, restriction.max_length.unwrap()),
                        });
                    }

                    // Check length (exact)
                    if restriction.length.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "length".to_string(),
                            strategy: FuzzStrategy::ViolateLength,
                            description: format!("Element {} has length={}", current_path, restriction.length.unwrap()),
                        });
                    }

                    // Check minInclusive
                    if restriction.min_inclusive.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "minInclusive".to_string(),
                            strategy: FuzzStrategy::ViolateMinInclusive,
                            description: format!("Element {} has minInclusive={}", current_path, restriction.min_inclusive.as_ref().unwrap()),
                        });
                    }

                    // Check maxInclusive
                    if restriction.max_inclusive.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "maxInclusive".to_string(),
                            strategy: FuzzStrategy::ViolateMaxInclusive,
                            description: format!("Element {} has maxInclusive={}", current_path, restriction.max_inclusive.as_ref().unwrap()),
                        });
                    }

                    // Check minExclusive
                    if restriction.min_exclusive.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "minExclusive".to_string(),
                            strategy: FuzzStrategy::ViolateMinExclusive,
                            description: format!("Element {} has minExclusive={}", current_path, restriction.min_exclusive.as_ref().unwrap()),
                        });
                    }

                    // Check maxExclusive
                    if restriction.max_exclusive.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "maxExclusive".to_string(),
                            strategy: FuzzStrategy::ViolateMaxExclusive,
                            description: format!("Element {} has maxExclusive={}", current_path, restriction.max_exclusive.as_ref().unwrap()),
                        });
                    }

                    // Check pattern
                    if restriction.pattern.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "pattern".to_string(),
                            strategy: FuzzStrategy::ViolatePattern,
                            description: format!("Element {} has pattern constraint", current_path),
                        });
                    }

                    // Check totalDigits
                    if restriction.total_digits.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "totalDigits".to_string(),
                            strategy: FuzzStrategy::ViolateTotalDigits,
                            description: format!("Element {} has totalDigits={}", current_path, restriction.total_digits.unwrap()),
                        });
                    }

                    // Check fractionDigits
                    if restriction.fraction_digits.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "fractionDigits".to_string(),
                            strategy: FuzzStrategy::ViolateFractionDigits,
                            description: format!("Element {} has fractionDigits={}", current_path, restriction.fraction_digits.unwrap()),
                        });
                    }

                    // Check whiteSpace
                    if restriction.white_space.is_some() {
                        violations.push(ConstraintViolation {
                            element_path: current_path.clone(),
                            constraint_type: "whiteSpace".to_string(),
                            strategy: FuzzStrategy::ViolateWhiteSpace,
                            description: format!("Element {} has whiteSpace={}", current_path, restriction.white_space.as_ref().unwrap()),
                        });
                    }
                }

                // Check for choice constraints
                if !typ.choice.is_empty() {
                    violations.push(ConstraintViolation {
                        element_path: current_path.clone(),
                        constraint_type: "choice".to_string(),
                        strategy: FuzzStrategy::ViolateChoice,
                        description: format!("Element {} has choice constraint", current_path),
                    });
                }

                // Check for sequence constraints
                if !typ.sequence.is_empty() {
                    violations.push(ConstraintViolation {
                        element_path: current_path.clone(),
                        constraint_type: "sequence".to_string(),
                        strategy: FuzzStrategy::ViolateSequenceOrder,
                        description: format!("Element {} has sequence constraint", current_path),
                    });
                }
            }

            // Check fixed value
            if element.fixed_value.is_some() {
                violations.push(ConstraintViolation {
                    element_path: current_path.clone(),
                    constraint_type: "fixed_value".to_string(),
                    strategy: FuzzStrategy::ViolateFixedValue,
                    description: format!("Element {} has fixed value", current_path),
                });
            }

            // Check nillable
            if element.nillable {
                violations.push(ConstraintViolation {
                    element_path: current_path.clone(),
                    constraint_type: "nillable".to_string(),
                    strategy: FuzzStrategy::ViolateNillable,
                    description: format!("Element {} is nillable", current_path),
                });
            }

            // Recursively check children
            for child_name in &element.children {
                if let Some(child_elem) = schema.get_element(child_name) {
                    discover_in_element(schema, child_elem, &current_path, violations);
                } else {
                    // Child might be defined inline in a complex type
                    // Create a virtual element for discovery
                    let virtual_elem = XsdElement {
                        name: child_name.clone(),
                        element_type: String::new(),
                        min_occurs: None,
                        max_occurs: None,
                        children: Vec::new(),
                        attributes: Vec::new(),
                        default_value: None,
                        fixed_value: None,
                        nillable: false,
                        r#abstract: false,
                        substitution_group: None,
                    };
                    discover_in_element(schema, &virtual_elem, &current_path, violations);
                }
            }

            // Also check children from type if element references a complex type
            // This is important because elements defined in sequences are stored in schema.elements
            // but their relationship to the parent type is only in typ.sequence
            if !element.element_type.is_empty() {
                let type_name = element.element_type.split(':').last().unwrap_or(&element.element_type);
                if let Some(typ) = schema.get_type(type_name) {
                    // Check children from sequence - these are element names that should exist in schema.elements
                    for child_name in &typ.sequence {
                        // Try to find the element in schema.elements (it should be there)
                        if let Some(child_elem) = schema.get_element(child_name) {
                            // Found the element - recursively discover violations in it
                            discover_in_element(schema, child_elem, &current_path, violations);
                        }
                        // If element not found, it might be defined inline with a different structure
                        // but in our parser, all elements should be in schema.elements
                    }
                }
            }
        }

        // Start discovery from root element
        if let Some(elem) = self.schema.get_element(root_element) {
            // Check if element has children directly or through its type
            let mut elem_to_discover = elem.clone();
            
            // If element has a type but no children, try to get children from the type
            if elem_to_discover.children.is_empty() && !elem_to_discover.element_type.is_empty() {
                let type_name = elem_to_discover.element_type.split(':').last().unwrap_or(&elem_to_discover.element_type);
                if let Some(typ) = self.schema.get_type(type_name) {
                    // Copy children from type to element for discovery
                    elem_to_discover.children = typ.sequence.clone();
                }
            }
            
            discover_in_element(&self.schema, &elem_to_discover, "", &mut violations);
        } else {
            // If root element not found, try to discover from all elements
            for (name, elem) in &self.schema.elements {
                if name == root_element {
                    discover_in_element(&self.schema, elem, "", &mut violations);
                    break;
                }
            }
        }

        // Always discover from all elements in schema that are children of root
        // This ensures we find all violations even if the recursive discovery missed some
        {
            // Get root type to check which elements are children
            let root_type_sequence = self.schema.get_element(root_element)
                .and_then(|root_elem| {
                    let root_type_name_full = &root_elem.element_type;
                    let root_type_name_short = root_elem.element_type.split(':').last().unwrap_or(&root_elem.element_type);
                    self.schema.get_type(root_type_name_full)
                        .or_else(|| self.schema.get_type(root_type_name_short))
                })
                .map(|root_type| root_type.sequence.clone())
                .unwrap_or_default();
            
            // Discover violations from all elements that reference types with restrictions
            // Process ALL elements that are children of root OR have types with restrictions
            for (elem_name, elem) in &self.schema.elements {
                // Skip the root element as we already tried it
                if elem_name == root_element {
                    continue;
                }
                
                // Determine if this element is a child of the root element
                // Since root_type_sequence might be empty due to parsing issues,
                // we'll assume elements with types that match known child element names are children
                let is_child_of_root = root_type_sequence.contains(elem_name);
                
                // Build proper path - use root/elem for children of root
                // For elements that reference custom types (tns:*), assume they're children of root
                let path = if is_child_of_root || elem.element_type.starts_with("tns:") {
                    format!("{}/{}", root_element, elem_name)
                } else {
                    // For elements not in root sequence, still check them if they have a type
                    elem_name.clone()
                };
                
                // Check element's type for restrictions
                // Only process if element has a type (elements without type can't have type restrictions)
                if !elem.element_type.is_empty() {
                    let type_name_full = &elem.element_type;
                    let type_name_short = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
                    
                    // Try to find the type - try short name first (most common case)
                    // Types are stored without namespace prefix in the schema
                    let typ = self.schema.get_type(type_name_short)
                        .or_else(|| self.schema.get_type(type_name_full));
                    
                    // Process this element if it has a type with restrictions
                    if let Some(typ) = typ {
                        if let Some(ref restriction) = typ.restriction {
                            // Element has a type with restrictions - discover all violations
                            // Check enumeration
                            if !restriction.enumeration.is_empty() {
                                violations.push(ConstraintViolation {
                                    element_path: path.clone(),
                                    constraint_type: "enumeration".to_string(),
                                    strategy: FuzzStrategy::InvalidEnum,
                                    description: format!("Element {} has enumeration constraint", path),
                                });
                            }
                            
                            // Check minLength
                            if restriction.min_length.is_some() {
                                violations.push(ConstraintViolation {
                                    element_path: path.clone(),
                                    constraint_type: "minLength".to_string(),
                                    strategy: FuzzStrategy::ViolateMinLength,
                                    description: format!("Element {} has minLength={}", path, restriction.min_length.unwrap()),
                                });
                            }
                        
                            // Check maxLength
                            if restriction.max_length.is_some() {
                            violations.push(ConstraintViolation {
                                element_path: path.clone(),
                                constraint_type: "maxLength".to_string(),
                                strategy: FuzzStrategy::ViolateMaxLength,
                                description: format!("Element {} has maxLength={}", path, restriction.max_length.unwrap()),
                            });
                        }
                        
                            // Check length (exact)
                            if restriction.length.is_some() {
                            violations.push(ConstraintViolation {
                                element_path: path.clone(),
                                constraint_type: "length".to_string(),
                                strategy: FuzzStrategy::ViolateLength,
                                description: format!("Element {} has length={}", path, restriction.length.unwrap()),
                            });
                        }
                        
                            // Check minInclusive
                            if restriction.min_inclusive.is_some() {
                                violations.push(ConstraintViolation {
                                    element_path: path.clone(),
                                    constraint_type: "minInclusive".to_string(),
                                    strategy: FuzzStrategy::ViolateMinInclusive,
                                    description: format!("Element {} has minInclusive={}", path, restriction.min_inclusive.as_ref().unwrap()),
                                });
                            }
                            
                            // Check maxInclusive
                            if restriction.max_inclusive.is_some() {
                                violations.push(ConstraintViolation {
                                    element_path: path.clone(),
                                    constraint_type: "maxInclusive".to_string(),
                                    strategy: FuzzStrategy::ViolateMaxInclusive,
                                    description: format!("Element {} has maxInclusive={}", path, restriction.max_inclusive.as_ref().unwrap()),
                                });
                            }
                        
                            // Check minExclusive
                            if restriction.min_exclusive.is_some() {
                            violations.push(ConstraintViolation {
                                element_path: path.clone(),
                                constraint_type: "minExclusive".to_string(),
                                strategy: FuzzStrategy::ViolateMinExclusive,
                                description: format!("Element {} has minExclusive={}", path, restriction.min_exclusive.as_ref().unwrap()),
                            });
                        }
                        
                            // Check maxExclusive
                            if restriction.max_exclusive.is_some() {
                            violations.push(ConstraintViolation {
                                element_path: path.clone(),
                                constraint_type: "maxExclusive".to_string(),
                                strategy: FuzzStrategy::ViolateMaxExclusive,
                                description: format!("Element {} has maxExclusive={}", path, restriction.max_exclusive.as_ref().unwrap()),
                            });
                        }
                        
                            // Check pattern
                            if restriction.pattern.is_some() {
                            violations.push(ConstraintViolation {
                                element_path: path.clone(),
                                constraint_type: "pattern".to_string(),
                                strategy: FuzzStrategy::ViolatePattern,
                                description: format!("Element {} has pattern constraint", path),
                            });
                        }
                        
                            // Check totalDigits
                            if restriction.total_digits.is_some() {
                            violations.push(ConstraintViolation {
                                element_path: path.clone(),
                                constraint_type: "totalDigits".to_string(),
                                strategy: FuzzStrategy::ViolateTotalDigits,
                                description: format!("Element {} has totalDigits={}", path, restriction.total_digits.unwrap()),
                            });
                        }
                        
                            // Check fractionDigits
                            if restriction.fraction_digits.is_some() {
                            violations.push(ConstraintViolation {
                                element_path: path.clone(),
                                constraint_type: "fractionDigits".to_string(),
                                strategy: FuzzStrategy::ViolateFractionDigits,
                                description: format!("Element {} has fractionDigits={}", path, restriction.fraction_digits.unwrap()),
                            });
                        }
                        
                            // Check whiteSpace
                            if restriction.white_space.is_some() {
                            violations.push(ConstraintViolation {
                                element_path: path.clone(),
                                constraint_type: "whiteSpace".to_string(),
                                strategy: FuzzStrategy::ViolateWhiteSpace,
                                description: format!("Element {} has whiteSpace={}", path, restriction.white_space.as_ref().unwrap()),
                            });
                        }
                    }
                }
                
                // Check element's own constraints (minOccurs, maxOccurs, attributes)
                // Only if element is a child of root (to avoid duplicates and focus on root's children)
                // Also check if element has a custom type (tns:*) as it's likely a child
                if is_child_of_root || elem.element_type.starts_with("tns:") {
                    if elem.min_occurs.is_some() && elem.min_occurs.unwrap() > 0 {
                        violations.push(ConstraintViolation {
                            element_path: path.clone(),
                            constraint_type: "minOccurs".to_string(),
                            strategy: FuzzStrategy::ViolateMinOccurs,
                            description: format!("Element {} has minOccurs={}", path, elem.min_occurs.unwrap()),
                        });
                    }
                    
                    if elem.max_occurs.is_some() {
                        let max_occurs_str = if elem.max_occurs.unwrap() == u32::MAX {
                            "unbounded".to_string()
                        } else {
                            elem.max_occurs.unwrap().to_string()
                        };
                        violations.push(ConstraintViolation {
                            element_path: path.clone(),
                            constraint_type: "maxOccurs".to_string(),
                            strategy: FuzzStrategy::ViolateMaxOccurs,
                            description: format!("Element {} has maxOccurs={}", path, max_occurs_str),
                        });
                    }
                    
                    for attr in &elem.attributes {
                        if attr.required {
                            violations.push(ConstraintViolation {
                                element_path: path.clone(),
                                constraint_type: "required_attribute".to_string(),
                                strategy: FuzzStrategy::MissingRequiredAttribute,
                                description: format!("Attribute {} is required on {}", attr.name, path),
                            });
                        }
                    }
                    }
                }
            }
        }

        violations
    }

    /// Generate XML files for all discovered constraint violations
    /// Each violation gets its own XML file with exactly one constraint violation
    /// Applied to the specific element path indicated in the violation
    pub fn generate_all_violations(&mut self, root_element: &str) -> Vec<(ConstraintViolation, String)> {
        let violations = self.discover_all_violations(root_element);
        let mut results = Vec::new();

        // Create a single-violation fuzzer for each violation
        // Each violation targets a specific element path
        for violation in violations {
            let mut single_fuzzer = XmlFuzzer::new_single_violation(self.schema.clone());
            // Pass the target element path to the fuzzing method
            let xml = single_fuzzer.fuzz_with_target(root_element, violation.strategy, &violation.element_path);
            results.push((violation, xml));
        }

        results
    }

    /// Apply fuzzing strategy targeting a specific element path
    /// Only applies the violation to the element matching the target path
    pub fn fuzz_with_target(&mut self, root_element: &str, strategy: FuzzStrategy, target_path: &str) -> String {
        match strategy {
            FuzzStrategy::ViolateMinOccurs => self.fuzz_violate_min_occurs_target(root_element, target_path),
            FuzzStrategy::ViolateMaxOccurs => self.fuzz_violate_max_occurs_target(root_element, target_path),
            FuzzStrategy::ViolateMinLength => self.fuzz_violate_min_length_target(root_element, target_path),
            FuzzStrategy::ViolateMaxLength => self.fuzz_violate_max_length_target(root_element, target_path),
            FuzzStrategy::ViolateMinInclusive => self.fuzz_violate_min_inclusive_target(root_element, target_path),
            FuzzStrategy::ViolateMaxInclusive => self.fuzz_violate_max_inclusive_target(root_element, target_path),
            FuzzStrategy::ViolateMinExclusive => self.fuzz_violate_min_exclusive_target(root_element, target_path),
            FuzzStrategy::ViolateMaxExclusive => self.fuzz_violate_max_exclusive_target(root_element, target_path),
            FuzzStrategy::InvalidEnum => self.fuzz_invalid_enum_target(root_element, target_path),
            FuzzStrategy::MissingRequiredAttribute => self.fuzz_missing_required_attribute_target(root_element, target_path),
            FuzzStrategy::ViolatePattern => self.fuzz_violate_pattern_target(root_element, target_path),
            FuzzStrategy::ViolateTotalDigits => self.fuzz_violate_total_digits_target(root_element, target_path),
            FuzzStrategy::ViolateFractionDigits => self.fuzz_violate_fraction_digits_target(root_element, target_path),
            FuzzStrategy::ViolateLength => self.fuzz_violate_length_target(root_element, target_path),
            FuzzStrategy::ViolateWhiteSpace => self.fuzz_violate_white_space_target(root_element, target_path),
            FuzzStrategy::ViolateFixedValue => self.fuzz_violate_fixed_value_target(root_element, target_path),
            FuzzStrategy::ViolateNillable => self.fuzz_violate_nillable_target(root_element, target_path),
            // For other strategies, use default behavior
            _ => self.fuzz(root_element, strategy),
        }
    }

    /// Apply all fuzzing strategies and return results for each
    /// Useful for comprehensive testing of all constraint violations
    pub fn fuzz_all(&mut self, root_element: &str) -> Vec<(FuzzStrategy, String)> {
        // List of all available fuzzing strategies
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

        // Apply each strategy and collect results
        strategies
            .into_iter()
            .map(|strategy| {
                let fuzzed = self.fuzz(root_element, strategy);
                (strategy, fuzzed)
            })
            .collect()
    }

    /// Add an unexpected element to violate schema structure
    /// Inserts elements that are not defined in the schema
    fn fuzz_add_element(&mut self, root_element: &str) -> String {
        // Start with valid XML
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

    /// Remove a required element to violate minOccurs constraints
    /// Deletes elements that should be present according to the schema
    fn fuzz_remove_element(&mut self, root_element: &str) -> String {
        // Start with valid XML
        let mut xml = self.generator.generate_valid(root_element);
        
        // Remove a random element to create invalid structure
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

    /// Generate values outside allowed ranges (min/max constraints)
    /// Violates numeric and length restrictions
    fn fuzz_out_of_range_value(&mut self, root_element: &str) -> String {
        // Start with valid XML
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values and make them out of range (stop after first if enabled)
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.fuzz_element_values(&mut xml, &elem_clone, true);
        }
        
        xml
    }

    /// Use invalid enumeration values
    /// Replaces valid enum values with values not in the allowed list
    fn fuzz_invalid_enum(&mut self, root_element: &str) -> String {
        // Start with valid XML
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find enumeration values and replace with invalid ones (stop after first if enabled)
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            self.fuzz_enum_values(&mut xml, &elem_clone);
        }
        
        xml
    }

    /// Violate enumeration on a specific target element
    fn fuzz_invalid_enum_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if !restriction.enumeration.is_empty() {
                        // Find and replace enum value in target element
                        let pattern = format!(r"(<{}[^>]*>)([^<]+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                            let invalid_value = format!("INVALID_{}", &caps[2]);
                            format!("{}{}{}", &caps[1], invalid_value, &caps[3])
                        }).to_string();
                    }
                }
            }
        }
        xml
    }

    /// Add attributes that are not defined in the schema
    /// Tests handling of unexpected attributes
    fn fuzz_invalid_attribute(&mut self, root_element: &str) -> String {
        // Start with valid XML
        let mut xml = self.generator.generate_valid(root_element);
        
        // Add invalid attributes that don't exist in schema
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

    /// Remove required attributes to violate schema constraints
    /// Tests validation of use="required" attributes
    fn fuzz_missing_required_attribute(&mut self, root_element: &str) -> String {
        // Start with valid XML
        let mut xml = self.generator.generate_valid(root_element);
        
        // Remove required attributes to create invalid XML
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

    /// Violate required attribute on a specific target element
    fn fuzz_missing_required_attribute_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        if let Some(elem) = self.schema.get_element(element_name) {
            for attr in &elem.attributes {
                if attr.required {
                    // Remove the required attribute from the target element
                    let pattern = format!(r#"(<{}[^>]*)\s+{}=\"[^\"]*\"([^>]*>)"#, element_name, attr.name);
                    let re = Regex::new(&pattern).unwrap();
                    xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                        format!("{}{}", &caps[1], &caps[2])
                    }).to_string();
                    break; // Only remove one attribute per violation
                }
            }
        }
        xml
    }

    /// Replace values with incorrect types (e.g., string instead of int)
    /// Violates type constraints defined in the schema
    fn fuzz_invalid_type(&mut self, root_element: &str) -> String {
        // Start with valid XML
        let mut xml = self.generator.generate_valid(root_element);
        
        // Replace numeric values with strings, etc. to violate types
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

    /// Fuzz element values, stopping after first violation if stop_after_first is true
    /// Returns true if a violation was applied, false otherwise
    fn fuzz_element_values(&mut self, xml: &mut String, element: &XsdElement, out_of_range: bool) -> bool {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if !restriction.enumeration.is_empty() {
                    return false; // Handled separately
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
                        if re.is_match(xml) {
                            *xml = re.replace(xml, &replacement).to_string();
                            return true; // Violation applied
                        }
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
                        if re.is_match(xml) {
                            *xml = re.replace(xml, &replacement).to_string();
                            return true; // Violation applied
                        }
                    }
                    _ => {}
                }
            }
        }

        // Recursively fuzz children (only if not stopping after first)
        if !self.stop_after_first {
            for child_name in &element.children {
                if let Some(child_elem) = self.schema.get_element(child_name) {
                    let child_clone = child_elem.clone();
                    if self.fuzz_element_values(xml, &child_clone, out_of_range) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Fuzz enumeration values, stopping after first violation if stop_after_first is true
    /// Returns true if a violation was applied, false otherwise
    fn fuzz_enum_values(&mut self, xml: &mut String, element: &XsdElement) -> bool {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                if !restriction.enumeration.is_empty() {
                    // Replace valid enum value with invalid one
                    for valid_value in &restriction.enumeration {
                        if xml.contains(valid_value) {
                            let invalid_value = format!("INVALID_{}", valid_value);
                            *xml = xml.replace(valid_value, &invalid_value);
                            return true; // Violation applied
                        }
                    }
                }
            }
        }

        // Recursively fuzz children (only if not stopping after first)
        if !self.stop_after_first {
            for child_name in &element.children {
                if let Some(child_elem) = self.schema.get_element(child_name) {
                    let child_clone = child_elem.clone();
                    if self.fuzz_enum_values(xml, &child_clone) {
                        return true;
                    }
                }
            }
        }
        false
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

    /// Violate minOccurs on a specific target element
    fn fuzz_violate_min_occurs_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Extract element name from target path (last component)
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        
        // Find and remove the target element to violate minOccurs
        let pattern = format!(r"<{}[^>]*>.*?</{}>", element_name, element_name);
        let re = Regex::new(&pattern).unwrap();
        if re.is_match(&xml) {
            // Remove the first occurrence of this element
            xml = re.replace(&xml, "").to_string();
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

    /// Violate maxOccurs on a specific target element
    fn fuzz_violate_max_occurs_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Extract element name from target path
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        
        // Find the target element and duplicate it to violate maxOccurs
        let pattern = format!(r"(<{}[^>]*>.*?</{}>)", element_name, element_name);
        let re = Regex::new(&pattern).unwrap();
        if let Some(caps) = re.captures(&xml) {
            let _element_content = &caps[1];
            // Insert a duplicate right after the original
            xml = re.replace(&xml, |caps: &regex::Captures| -> String {
                format!("{}{}", &caps[0], &caps[0])
            }).to_string();
        }
        
        xml
    }

    fn fuzz_violate_min_length(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find string values with minLength restrictions and make them too short
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            let _ = self.violate_length_constraints(&mut xml, &elem_clone, true);
        }
        
        xml
    }

    /// Violate minLength on a specific target element
    fn fuzz_violate_min_length_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Extract element name from target path
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        
        // Find the target element and get its minLength constraint
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if let Some(min_len) = restriction.min_length {
                        // Find and modify the target element's content
                        let pattern = format!(r"(<{}[^>]*>)([^<]+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                            let _value = &caps[2];
                            // Make value shorter than minLength
                            let new_value = "x".repeat((min_len as usize).saturating_sub(1));
                            format!("{}{}{}", &caps[1], new_value, &caps[3])
                        }).to_string();
                    }
                }
            }
        }
        
        xml
    }

    fn fuzz_violate_max_length(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find string values with maxLength restrictions and make them too long
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            let _ = self.violate_length_constraints(&mut xml, &elem_clone, false);
        }
        
        xml
    }

    /// Violate maxLength on a specific target element
    fn fuzz_violate_max_length_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Extract element name from target path
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        
        // Find the target element and get its maxLength constraint
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if let Some(max_len) = restriction.max_length {
                        // Find and modify the target element's content
                        let pattern = format!(r"(<{}[^>]*>)([^<]+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                            // Make value longer than maxLength
                            let new_value = "x".repeat(max_len as usize + 100);
                            format!("{}{}{}", &caps[1], new_value, &caps[3])
                        }).to_string();
                    }
                }
            }
        }
        
        xml
    }

    fn fuzz_violate_min_inclusive(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values with minInclusive and make them below the minimum
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            let _ = self.violate_inclusive_constraints(&mut xml, &elem_clone, true);
        }
        
        xml
    }

    /// Violate minInclusive on a specific target element
    fn fuzz_violate_min_inclusive_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Extract element name from target path
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        
        // Find the target element and get its minInclusive constraint
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if let Some(min_val) = &restriction.min_inclusive {
                        // Find and modify the target element's numeric value
                        let pattern = format!(r"(<{}[^>]*>)(\d+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        if let Ok(min_int) = min_val.parse::<i32>() {
                            xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                                // Replace with value below minimum
                                format!("{}{}{}", &caps[1], min_int - 1, &caps[3])
                            }).to_string();
                        }
                    }
                }
            }
        }
        
        xml
    }

    fn fuzz_violate_max_inclusive(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values with maxInclusive and make them above the maximum
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            let _ = self.violate_inclusive_constraints(&mut xml, &elem_clone, false);
        }
        
        xml
    }

    /// Violate maxInclusive on a specific target element
    fn fuzz_violate_max_inclusive_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Extract element name from target path
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        
        // Find the target element and get its maxInclusive constraint
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if let Some(max_val) = &restriction.max_inclusive {
                        // Find and modify the target element's numeric value
                        let pattern = format!(r"(<{}[^>]*>)(\d+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        if let Ok(max_int) = max_val.parse::<i32>() {
                            xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                                // Replace with value above maximum
                                format!("{}{}{}", &caps[1], max_int + 1, &caps[3])
                            }).to_string();
                        }
                    }
                }
            }
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

    /// Violate length constraints, stopping after first violation if stop_after_first is true
    /// Returns true if a violation was applied, false otherwise
    fn violate_length_constraints(&mut self, xml: &mut String, element: &XsdElement, is_min: bool) -> bool {
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

        // Recursively fuzz children (only if not stopping after first)
        if !self.stop_after_first {
            for child_name in &element.children {
                if let Some(child_elem) = self.schema.get_element(child_name) {
                    let child_clone = child_elem.clone();
                    if self.violate_length_constraints(xml, &child_clone, is_min) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Violate inclusive constraints, stopping after first violation if stop_after_first is true
    /// Returns true if a violation was applied, false otherwise
    fn violate_inclusive_constraints(&mut self, xml: &mut String, element: &XsdElement, is_min: bool) -> bool {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                match restriction.base.as_str() {
                    "xs:int" | "xs:integer" | "int" | "integer" => {
                        if is_min {
                            if let Some(min_val) = &restriction.min_inclusive {
                                if let Ok(min_int) = min_val.parse::<i32>() {
                                    // Replace with value below minimum
                                    let re = Regex::new(r"\d+").unwrap();
                                    if re.is_match(xml) {
                                        *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                            (min_int - 1).to_string()
                                        }).to_string();
                                        return true;
                                    }
                                }
                            }
                        } else {
                            if let Some(max_val) = &restriction.max_inclusive {
                                if let Ok(max_int) = max_val.parse::<i32>() {
                                    // Replace with value above maximum
                                    let re = Regex::new(r"\d+").unwrap();
                                    if re.is_match(xml) {
                                        *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                            (max_int + 1).to_string()
                                        }).to_string();
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    "xs:decimal" | "xs:double" | "xs:float" => {
                        if is_min {
                            if let Some(min_val) = &restriction.min_inclusive {
                                if let Ok(min_float) = min_val.parse::<f64>() {
                                    let re = Regex::new(r"\d+\.\d+").unwrap();
                                    if re.is_match(xml) {
                                        *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                            format!("{:.2}", min_float - 1.0)
                                        }).to_string();
                                        return true;
                                    }
                                }
                            }
                        } else {
                            if let Some(max_val) = &restriction.max_inclusive {
                                if let Ok(max_float) = max_val.parse::<f64>() {
                                    let re = Regex::new(r"\d+\.\d+").unwrap();
                                    if re.is_match(xml) {
                                        *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                            format!("{:.2}", max_float + 1.0)
                                        }).to_string();
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Recursively fuzz children (only if not stopping after first)
        if !self.stop_after_first {
            for child_name in &element.children {
                if let Some(child_elem) = self.schema.get_element(child_name) {
                    let child_clone = child_elem.clone();
                    if self.violate_inclusive_constraints(xml, &child_clone, is_min) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn fuzz_violate_min_exclusive(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values with minExclusive and make them equal to or below the minimum
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            let _ = self.violate_exclusive_constraints(&mut xml, &elem_clone, true);
        }
        
        xml
    }

    /// Violate minExclusive on a specific target element
    fn fuzz_violate_min_exclusive_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if let Some(min_val) = &restriction.min_exclusive {
                        let pattern = format!(r"(<{}[^>]*>)(\d+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        if let Ok(min_int) = min_val.parse::<i32>() {
                            xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                                format!("{}{}{}", &caps[1], min_int, &caps[3]) // Equal violates exclusive
                            }).to_string();
                        }
                    }
                }
            }
        }
        xml
    }

    fn fuzz_violate_max_exclusive(&mut self, root_element: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        
        // Find numeric values with maxExclusive and make them equal to or above the maximum
        if let Some(elem) = self.schema.get_element(root_element) {
            let elem_clone = elem.clone();
            let _ = self.violate_exclusive_constraints(&mut xml, &elem_clone, false);
        }
        
        xml
    }

    /// Violate maxExclusive on a specific target element
    fn fuzz_violate_max_exclusive_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if let Some(max_val) = &restriction.max_exclusive {
                        let pattern = format!(r"(<{}[^>]*>)(\d+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        if let Ok(max_int) = max_val.parse::<i32>() {
                            xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                                format!("{}{}{}", &caps[1], max_int, &caps[3]) // Equal violates exclusive
                            }).to_string();
                        }
                    }
                }
            }
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

    /// Violate pattern on a specific target element
    fn fuzz_violate_pattern_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        let pattern = format!(r"(<{}[^>]*>)([^<]+)(</{}>)", element_name, element_name);
        let re = Regex::new(&pattern).unwrap();
        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
            format!("{}INVALID_PATTERN_{}{}", &caps[1], &caps[2], &caps[3])
        }).to_string();
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

    /// Violate totalDigits on a specific target element
    fn fuzz_violate_total_digits_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if let Some(total_digits) = restriction.total_digits {
                        // Make number with more digits than allowed
                        let pattern = format!(r"(<{}[^>]*>)(\d+\.\d+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                            let long_number = "9".repeat((total_digits + 10) as usize);
                            format!("{}{}.99{}", &caps[1], long_number, &caps[3])
                        }).to_string();
                    }
                }
            }
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

    /// Violate fractionDigits on a specific target element
    fn fuzz_violate_fraction_digits_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if let Some(fraction_digits) = restriction.fraction_digits {
                        // Make number with more fraction digits than allowed
                        let pattern = format!(r"(<{}[^>]*>)(\d+\.\d+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                            let extra_fractions = "9".repeat((fraction_digits + 5) as usize);
                            // Include the closing tag (caps[3])
                            format!("{}123.{}{}", &caps[1], extra_fractions, &caps[3])
                        }).to_string();
                    }
                }
            }
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

    /// Violate fixed value on a specific target element
    fn fuzz_violate_fixed_value_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        let pattern = format!(r"(<{}[^>]*>)([^<]+)(</{}>)", element_name, element_name);
        let re = Regex::new(&pattern).unwrap();
        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
            format!("{}INVALID_{}{}", &caps[1], &caps[2], &caps[3])
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

    /// Violate nillable on a specific target element
    fn fuzz_violate_nillable_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        let pattern = format!(r"(<{}[^>]*)(>)([^<]*</{}>)", element_name, element_name);
        let re = Regex::new(&pattern).unwrap();
        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
            format!("{} xsi:nil=\"true\"{}{}", &caps[1], &caps[2], &caps[3])
        }).to_string();
        xml
    }

    /// Violate exclusive constraints, stopping after first violation if stop_after_first is true
    /// Returns true if a violation was applied, false otherwise
    fn violate_exclusive_constraints(&mut self, xml: &mut String, element: &XsdElement, is_min: bool) -> bool {
        if let Some(typ) = self.schema.get_type(&element.element_type) {
            if let Some(ref restriction) = typ.restriction {
                match restriction.base.as_str() {
                    "xs:int" | "xs:integer" | "int" | "integer" => {
                        if is_min {
                            if let Some(min_val) = &restriction.min_exclusive {
                                if let Ok(min_int) = min_val.parse::<i32>() {
                                    // Replace with value equal to or below minimum (violates exclusive)
                                    let re = Regex::new(r"\d+").unwrap();
                                    if re.is_match(xml) {
                                        *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                            min_int.to_string() // Equal to min violates exclusive
                                        }).to_string();
                                        return true;
                                    }
                                }
                            }
                        } else {
                            if let Some(max_val) = &restriction.max_exclusive {
                                if let Ok(max_int) = max_val.parse::<i32>() {
                                    // Replace with value equal to or above maximum (violates exclusive)
                                    let re = Regex::new(r"\d+").unwrap();
                                    if re.is_match(xml) {
                                        *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                            max_int.to_string() // Equal to max violates exclusive
                                        }).to_string();
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    "xs:decimal" | "xs:double" | "xs:float" => {
                        if is_min {
                            if let Some(min_val) = &restriction.min_exclusive {
                                if let Ok(min_float) = min_val.parse::<f64>() {
                                    let re = Regex::new(r"\d+\.\d+").unwrap();
                                    if re.is_match(xml) {
                                        *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                            format!("{:.2}", min_float) // Equal violates exclusive
                                        }).to_string();
                                        return true;
                                    }
                                }
                            }
                        } else {
                            if let Some(max_val) = &restriction.max_exclusive {
                                if let Ok(max_float) = max_val.parse::<f64>() {
                                    let re = Regex::new(r"\d+\.\d+").unwrap();
                                    if re.is_match(xml) {
                                        *xml = re.replace_all(xml, |_caps: &regex::Captures| -> String {
                                            format!("{:.2}", max_float) // Equal violates exclusive
                                        }).to_string();
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Recursively fuzz children (only if not stopping after first)
        if !self.stop_after_first {
            for child_name in &element.children {
                if let Some(child_elem) = self.schema.get_element(child_name) {
                    let child_clone = child_elem.clone();
                    if self.violate_exclusive_constraints(xml, &child_clone, is_min) {
                        return true;
                    }
                }
            }
        }
        false
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

    /// Violate length (exact) on a specific target element
    fn fuzz_violate_length_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        if let Some(elem) = self.schema.get_element(element_name) {
            let type_name = elem.element_type.split(':').last().unwrap_or(&elem.element_type);
            if let Some(typ) = self.schema.get_type(type_name) {
                if let Some(ref restriction) = typ.restriction {
                    if let Some(length) = restriction.length {
                        let pattern = format!(r"(<{}[^>]*>)([^<]+)(</{}>)", element_name, element_name);
                        let re = Regex::new(&pattern).unwrap();
                        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
                            // Make value with different length than required
                            let new_value = "x".repeat((length as usize) + 1);
                            format!("{}{}{}", &caps[1], new_value, &caps[3])
                        }).to_string();
                    }
                }
            }
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

    /// Violate whiteSpace on a specific target element
    fn fuzz_violate_white_space_target(&mut self, root_element: &str, target_path: &str) -> String {
        let mut xml = self.generator.generate_valid(root_element);
        let element_name = target_path.split('/').last().unwrap_or(target_path);
        let pattern = format!(r"(<{}[^>]*>)([^<]+)(</{}>)", element_name, element_name);
        let re = Regex::new(&pattern).unwrap();
        xml = re.replace_all(&xml, |caps: &regex::Captures| -> String {
            // Add extra whitespace to violate constraints
            format!("{}  {}  {}", &caps[1], &caps[2], &caps[3])
        }).to_string();
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

