use pyo3::prelude::*;
use humantime::format_duration;
use log::{debug, info};
use rayon::prelude::*;
use std::fs;
use std::io;
use std::path;
use std::time::Instant;
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize, Ord, PartialOrd)]
pub struct Node {
    pub id: String,
    pub category: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize, Ord, PartialOrd)]
pub struct Edge {
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub primary_knowledge_source: String,
    pub aggregator_knowledge_source: Option<String>,
    pub knowledge_level: String,
    pub agent_type: String,
}

#[pyfunction]
#[pyo3(signature = (input_path, output_format, report_path))]
// fn validate_edges(input_path: String, output_format: String, report_path: String) -> Result<(), Box<dyn std::error::Error>> {
fn validate_edges(input_path: String, output_format: String, report_path: String) -> PyResult<()> {
    let start = Instant::now();

    let edges_path = path::PathBuf::from(input_path);
    let data: Vec<Edge> = read_edges_file(&edges_path);

    let curie_regex = regex::Regex::new(r"^[A-Za-z_]+:.+$").expect("Could not create curie regex");
    let starts_with_biolink_regex = regex::Regex::new(r"^biolink:.+$").expect("Could not create biolink regex");

    let mut violations = vec![];
    
    let mut subject_column_validation_infractions: Vec<_> = data
        .par_iter()
        .filter_map(|n| match curie_regex.is_match(n.subject.as_str()) {
            true => None,
            false => Some(format!("Subject column does not have a valid CURIE: {:?}", n)),
        })
        .collect();
    violations.append(&mut subject_column_validation_infractions);

    let mut predicate_column_validation_infractions: Vec<_> = data
        .par_iter()
        .filter_map(|n| match starts_with_biolink_regex.is_match(n.predicate.as_str()) {
            true => None,
            false => Some(format!("Predicate column does start with 'biolink': {:?}", n)),
        })
        .collect();
    violations.append(&mut predicate_column_validation_infractions);

    let mut object_column_validation_infractions: Vec<_> = data
        .par_iter()
        .filter_map(|n| match curie_regex.is_match(n.object.as_str()) {
            true => None,
            false => Some(format!("Object column does not have a valid CURIE: {:?}", n)),
        })
        .collect();
    violations.append(&mut object_column_validation_infractions);

    let report = path::PathBuf::from(report_path);
    fs::write(report, violations.join("\n")).expect("Could not write violations report");

    info!("Duration: {}", format_duration(start.elapsed()).to_string());
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (input_path, output_format, report_path))]
// fn validate_nodes(input_path: String, output_format: String, report_path: String) -> Result<(), Box<dyn std::error::Error>> {
fn validate_nodes(input_path: String, output_format: String, report_path: String) -> PyResult<()> {
    let start = Instant::now();

    let nodes_path = path::PathBuf::from(input_path);
    let data: Vec<Node> = read_nodes_file(&nodes_path);

    let curie_regex = regex::Regex::new(r"^[A-Za-z_]+:.+$").expect("Could not create curie regex");
    let starts_with_biolink_regex = regex::Regex::new(r"^biolink:.+$").expect("Could not create biolink regex");

    let mut violations: Vec<String> = vec![];

    let mut id_column_validation_infractions: Vec<_> = data
        .par_iter()
        .filter_map(|n| match curie_regex.is_match(n.id.as_str()) {
            true => None,
            false => Some(format!("Id column does not have a valid CURIE: {:?}", n)),
        })
        .collect();
    violations.append(&mut id_column_validation_infractions);

    let mut category_column_validation_infractions: Vec<_> = data
        .par_iter()
        .filter_map(|n| match starts_with_biolink_regex.is_match(n.category.as_str()) {
            true => None,
            false => Some(format!("Category column does start with 'biolink': {:?}", n)),
        })
        .collect();
    violations.append(&mut category_column_validation_infractions);

    let report = path::PathBuf::from(report_path);
    fs::write(report, violations.join("\n")).expect("Could not write violations report");

    info!("Duration: {}", format_duration(start.elapsed()).to_string());
    Ok(())
}


fn read_nodes_file(nodes_path: &path::PathBuf) -> Vec<Node> {
    let nodes_file = fs::File::open(nodes_path.clone()).unwrap();
    let reader = io::BufReader::new(nodes_file);
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(true).delimiter(b'\t').from_reader(reader);
    let mut nodes = vec![];
    for result in rdr.deserialize() {
        let record: Node = result.unwrap();
        nodes.push(record.clone());
    }
    nodes
}

fn read_edges_file(edges_path: &path::PathBuf) -> Vec<Edge> {
    let edges_file = fs::File::open(edges_path.clone()).unwrap();
    let reader = io::BufReader::new(edges_file);
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(true).delimiter(b'\t').from_reader(reader);
    let mut edges = vec![];
    for result in rdr.deserialize() {
        let record: Edge = result.unwrap();
        edges.push(record.clone());
    }
    edges
}


#[pymodule]
fn rusty_mv(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(validate_edges, m)?)?;
    m.add_function(wrap_pyfunction!(validate_nodes, m)?)?;
    Ok(())
}

#[cfg(test)]
mod test {

    #[test]
    fn scratch() {
        let nodes = crate::read_nodes_file(&std::path::PathBuf::from("/home/jdr0887/workspace/github/everycure-org/matrix-validator/tests/data/testdata_robokop-kg_nodes.tsv"));
        assert_eq!(true, true);
    }

}