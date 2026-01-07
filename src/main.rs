//! XML Fuzzer Command-Line Interface
//! 
//! Provides a CLI tool for generating valid and fuzzed XML documents
//! based on XSD schema definitions.

use aixmlfuzzer::*;
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::fs;
use std::path::PathBuf;

/// Command-line interface definition using clap
/// Parses user arguments for XSD file, root element, output directory, and fuzzing strategy
#[derive(Parser)]
#[command(name = "aixmlfuzzer")]
#[command(about = "XML Fuzzer using XSD schema definitions", long_about = None)]
struct Cli {
    /// Path to the XSD schema file
    #[arg(short, long)]
    xsd: PathBuf,

    /// Root element name to generate/fuzz
    #[arg(short, long)]
    root: String,

    /// Output directory for generated XML files
    #[arg(short, long, default_value = "output")]
    output: PathBuf,

    /// Fuzzing strategy to use
    #[arg(short, long, value_enum)]
    strategy: Option<FuzzStrategyArg>,

    /// Number of fuzzed XML files to generate
    #[arg(short, long, default_value_t = 10)]
    count: u32,

    /// Generate valid XML instead of fuzzed
    #[arg(long)]
    valid: bool,

    /// Generate all constraint violations sequentially (one per file)
    /// Each file will contain exactly one constraint violation
    #[arg(long)]
    all_violations: bool,
}

/// CLI representation of fuzzing strategies
/// Maps command-line argument values to internal FuzzStrategy enum
#[derive(Clone, ValueEnum)]
enum FuzzStrategyArg {
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
    All,
}

/// Convert CLI strategy argument to internal FuzzStrategy enum
impl From<FuzzStrategyArg> for FuzzStrategy {
    fn from(arg: FuzzStrategyArg) -> Self {
        match arg {
            FuzzStrategyArg::AddElement => FuzzStrategy::AddElement,
            FuzzStrategyArg::RemoveElement => FuzzStrategy::RemoveElement,
            FuzzStrategyArg::OutOfRangeValue => FuzzStrategy::OutOfRangeValue,
            FuzzStrategyArg::InvalidEnum => FuzzStrategy::InvalidEnum,
            FuzzStrategyArg::InvalidAttribute => FuzzStrategy::InvalidAttribute,
            FuzzStrategyArg::MissingRequiredAttribute => FuzzStrategy::MissingRequiredAttribute,
            FuzzStrategyArg::InvalidType => FuzzStrategy::InvalidType,
            FuzzStrategyArg::MalformedXml => FuzzStrategy::MalformedXml,
            FuzzStrategyArg::ExtremeValues => FuzzStrategy::ExtremeValues,
            FuzzStrategyArg::BoundaryValues => FuzzStrategy::BoundaryValues,
            FuzzStrategyArg::ViolateMinOccurs => FuzzStrategy::ViolateMinOccurs,
            FuzzStrategyArg::ViolateMaxOccurs => FuzzStrategy::ViolateMaxOccurs,
            FuzzStrategyArg::ViolateMinLength => FuzzStrategy::ViolateMinLength,
            FuzzStrategyArg::ViolateMaxLength => FuzzStrategy::ViolateMaxLength,
            FuzzStrategyArg::ViolateMinInclusive => FuzzStrategy::ViolateMinInclusive,
            FuzzStrategyArg::ViolateMaxInclusive => FuzzStrategy::ViolateMaxInclusive,
            FuzzStrategyArg::ViolateMinExclusive => FuzzStrategy::ViolateMinExclusive,
            FuzzStrategyArg::ViolateMaxExclusive => FuzzStrategy::ViolateMaxExclusive,
            FuzzStrategyArg::ViolatePattern => FuzzStrategy::ViolatePattern,
            FuzzStrategyArg::ViolateTotalDigits => FuzzStrategy::ViolateTotalDigits,
            FuzzStrategyArg::ViolateFractionDigits => FuzzStrategy::ViolateFractionDigits,
            FuzzStrategyArg::ViolateChoice => FuzzStrategy::ViolateChoice,
            FuzzStrategyArg::ViolateSequenceOrder => FuzzStrategy::ViolateSequenceOrder,
            FuzzStrategyArg::ViolateFixedValue => FuzzStrategy::ViolateFixedValue,
            FuzzStrategyArg::ViolateNillable => FuzzStrategy::ViolateNillable,
            FuzzStrategyArg::ViolateLength => FuzzStrategy::ViolateLength,
            FuzzStrategyArg::ViolateWhiteSpace => FuzzStrategy::ViolateWhiteSpace,
            FuzzStrategyArg::ViolateAll => FuzzStrategy::ViolateAll,
            FuzzStrategyArg::ViolateUnique => FuzzStrategy::ViolateUnique,
            FuzzStrategyArg::ViolateKey => FuzzStrategy::ViolateKey,
            FuzzStrategyArg::ViolateKeyRef => FuzzStrategy::ViolateKeyRef,
            FuzzStrategyArg::ViolateDefault => FuzzStrategy::ViolateDefault,
            FuzzStrategyArg::ViolateAbstract => FuzzStrategy::ViolateAbstract,
            FuzzStrategyArg::ViolateMixed => FuzzStrategy::ViolateMixed,
            FuzzStrategyArg::ViolateUnion => FuzzStrategy::ViolateUnion,
            FuzzStrategyArg::ViolateList => FuzzStrategy::ViolateList,
            FuzzStrategyArg::ViolateAny => FuzzStrategy::ViolateAny,
            FuzzStrategyArg::ViolateAnyAttribute => FuzzStrategy::ViolateAnyAttribute,
            FuzzStrategyArg::ViolateXsiType => FuzzStrategy::ViolateXsiType,
            FuzzStrategyArg::ViolateSubstitutionGroup => FuzzStrategy::ViolateSubstitutionGroup,
            FuzzStrategyArg::All => FuzzStrategy::AddElement, // Placeholder
        }
    }
}

/// Main entry point for the XML fuzzer CLI
/// Orchestrates XSD parsing, XML generation/fuzzing, and file output
fn main() -> Result<()> {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Read and parse XSD schema file
    println!("Reading XSD schema from: {:?}", cli.xsd);
    let xsd_content = fs::read_to_string(&cli.xsd)
        .with_context(|| format!("Failed to read XSD file: {:?}", cli.xsd))?;

    // Parse XSD content into internal schema representation
    println!("Parsing XSD schema...");
    let schema = XsdSchema::parse(&xsd_content)
        .context("Failed to parse XSD schema")?;

    // Display parsing results
    println!("Found {} elements and {} types", schema.elements.len(), schema.types.len());

    // Ensure output directory exists
    fs::create_dir_all(&cli.output)
        .with_context(|| format!("Failed to create output directory: {:?}", cli.output))?;

    // Branch based on whether user wants valid or fuzzed XML
    if cli.valid {
        // Generate valid XML conforming to the schema
        let mut generator = XmlGenerator::new(schema);
        for i in 0..cli.count {
            let xml = generator.generate_valid(&cli.root);
            let output_path = cli.output.join(format!("valid_{:04}.xml", i));
            fs::write(&output_path, xml)
                .with_context(|| format!("Failed to write file: {:?}", output_path))?;
            println!("Generated valid XML: {:?}", output_path);
        }
    } else if cli.all_violations {
        // Generate all constraint violations sequentially (one per file)
        let mut fuzzer = XmlFuzzer::new(schema);
        let violations = fuzzer.generate_all_violations(&cli.root);
        
        println!("Discovered {} constraint violations", violations.len());
        
        for (i, (violation, xml)) in violations.iter().enumerate() {
            let safe_path = violation.element_path.replace("/", "_");
            let safe_constraint = violation.constraint_type.replace(" ", "_");
            let output_path = cli.output.join(format!(
                "violation_{:04}_{}_{}.xml",
                i, safe_path, safe_constraint
            ));
            fs::write(&output_path, xml)
                .with_context(|| format!("Failed to write file: {:?}", output_path))?;
            println!("Generated violation {}: {} - {}", i + 1, violation.element_path, violation.description);
        }
    } else {
        // Generate fuzzed XML using specified or random strategies
        let mut fuzzer = XmlFuzzer::new(schema);

        // Check if a specific fuzzing strategy was requested
        if let Some(strategy_arg) = cli.strategy {
            match strategy_arg {
                FuzzStrategyArg::All => {
                    // Generate XML using all available fuzzing strategies
                    for i in 0..cli.count {
                        let results = fuzzer.fuzz_all(&cli.root);
                        // Write each strategy's output to a separate file
                        for (strategy, xml) in results {
                            let strategy_name = format!("{:?}", strategy);
                            let output_path = cli.output.join(format!("fuzz_{}_{:04}.xml", strategy_name, i));
                            fs::write(&output_path, xml)
                                .with_context(|| format!("Failed to write file: {:?}", output_path))?;
                            println!("Generated fuzzed XML ({:?}): {:?}", strategy, output_path);
                        }
                    }
                }
                _ => {
                    // Generate XML using a single specified strategy
                    let strategy: FuzzStrategy = strategy_arg.into();
                    for i in 0..cli.count {
                        let xml = fuzzer.fuzz(&cli.root, strategy);
                        let strategy_name = format!("{:?}", strategy);
                        let output_path = cli.output.join(format!("fuzz_{}_{:04}.xml", strategy_name, i));
                        fs::write(&output_path, xml)
                            .with_context(|| format!("Failed to write file: {:?}", output_path))?;
                        println!("Generated fuzzed XML ({:?}): {:?}", strategy, output_path);
                    }
                }
            }
        } else {
            // No strategy specified - use a random selection from common strategies
            let strategies = vec![
                FuzzStrategy::AddElement,
                FuzzStrategy::RemoveElement,
                FuzzStrategy::OutOfRangeValue,
                FuzzStrategy::InvalidEnum,
                FuzzStrategy::InvalidAttribute,
                FuzzStrategy::MissingRequiredAttribute,
                FuzzStrategy::ExtremeValues,
                FuzzStrategy::BoundaryValues,
            ];

            for i in 0..cli.count {
                let strategy = strategies[i as usize % strategies.len()];
                let xml = fuzzer.fuzz(&cli.root, strategy);
                let strategy_name = format!("{:?}", strategy);
                let output_path = cli.output.join(format!("fuzz_{}_{:04}.xml", strategy_name, i));
                fs::write(&output_path, xml)
                    .with_context(|| format!("Failed to write file: {:?}", output_path))?;
                println!("Generated fuzzed XML ({:?}): {:?}", strategy, output_path);
            }
        }
    }

    println!("\nDone! Generated files in: {:?}", cli.output);
    Ok(())
}

