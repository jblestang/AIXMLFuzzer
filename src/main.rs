use aixmlfuzzer::*;
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::fs;
use std::path::PathBuf;

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
}

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

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Read XSD file
    println!("Reading XSD schema from: {:?}", cli.xsd);
    let xsd_content = fs::read_to_string(&cli.xsd)
        .with_context(|| format!("Failed to read XSD file: {:?}", cli.xsd))?;

    // Parse XSD
    println!("Parsing XSD schema...");
    let schema = XsdSchema::parse(&xsd_content)
        .context("Failed to parse XSD schema")?;

    println!("Found {} elements and {} types", schema.elements.len(), schema.types.len());

    // Create output directory
    fs::create_dir_all(&cli.output)
        .with_context(|| format!("Failed to create output directory: {:?}", cli.output))?;

    if cli.valid {
        // Generate valid XML
        let mut generator = XmlGenerator::new(schema);
        for i in 0..cli.count {
            let xml = generator.generate_valid(&cli.root);
            let output_path = cli.output.join(format!("valid_{:04}.xml", i));
            fs::write(&output_path, xml)
                .with_context(|| format!("Failed to write file: {:?}", output_path))?;
            println!("Generated valid XML: {:?}", output_path);
        }
    } else {
        // Generate fuzzed XML
        let mut fuzzer = XmlFuzzer::new(schema);

        if let Some(strategy_arg) = cli.strategy {
            match strategy_arg {
                FuzzStrategyArg::All => {
                    // Generate all strategies
                    for i in 0..cli.count {
                        let results = fuzzer.fuzz_all(&cli.root);
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
            // Use random strategies
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

