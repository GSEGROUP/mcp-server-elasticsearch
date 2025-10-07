// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
use crate::servers::elasticsearch::{EsClientProvider, read_json};
//use elasticsearch::cat::{CatIndicesParts, CatShardsParts};
//use elasticsearch::indices::IndicesGetMappingParts;
use elasticsearch::{Elasticsearch};//, SearchParts};
use indexmap::IndexMap;
use rmcp::handler::server::tool::{Parameters, ToolRouter};
use rmcp::model::{
    CallToolResult, Content, Implementation, JsonObject, ProtocolVersion, ServerCapabilities, ServerInfo,
    ErrorCode,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler};
use rmcp_macros::{tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use http::request::Parts;

#[derive(Clone)]
pub struct EsBaseTools {
    es_client: EsClientProvider,
    tool_router: ToolRouter<EsBaseTools>,
}

impl EsBaseTools {
    pub fn new(es_client: Elasticsearch) -> Self {
        Self {
            es_client: EsClientProvider::new(es_client),
            tool_router: Self::tool_router(),
        }
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListIndicesParams {
    /// Index pattern of Elasticsearch indices to list
    pub index_pattern: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetMappingsParams {
    /// Name of the Elasticsearch index to get mappings for
    index: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SearchParams {
    /// Name of the Elasticsearch index to search
    index: String,

    /// Name of the fields that need to be returned (optional)
    fields: Option<Vec<String>>,

    /// Complete Elasticsearch query DSL object that can include query, size, from, sort, etc.
    query_body: Map<String, Value>, // note: just Value doesn't work, as Claude would send a string
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct EsqlQueryParams {
    /// Complete Elasticsearch ES|QL query
    query: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetShardsParams {
    /// Optional index name to get shard information for
    index: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DebugHeadersParams {}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SearchGseDocumentLibraryParams {
    user_query: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetDocumentsParams {
    /// Terme de recherche pour les documents
    query: String,

    /// ID du site pour filtrer les documents (optionnel)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site_id: Option<String>,
}

#[tool_router]
impl EsBaseTools {
    // Fonctions générales : 
    fn extract_bearer_token(req_ctx: &RequestContext<RoleServer>) -> Result<&str, rmcp::Error> {
    req_ctx
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.headers.get("authorization"))
        .and_then(|value| value.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or_else(|| rmcp::Error::new(
            ErrorCode::INVALID_PARAMS,
            "Missing or invalid authorization token".to_string(),
            None,
        ))
}

    async fn fetch_user_email(token: &str) -> Result<String, rmcp::Error> {
    use reqwest::Client;
    let client = Client::new();
    let graph_response = client
        .get("https://graph.microsoft.com/v1.0/me")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| rmcp::Error::new(
            ErrorCode::INTERNAL_ERROR,
            format!("Failed to call Microsoft Graph API: {}", e),
            None,
        ))?;

    let graph_data: Value = graph_response
        .json()
        .await
        .map_err(|e| rmcp::Error::new(
            ErrorCode::INTERNAL_ERROR,
            format!("Failed to parse Microsoft Graph API response: {}", e),
            None,
        ))?;

    graph_data
        .get("mail")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| rmcp::Error::new(
            ErrorCode::INTERNAL_ERROR,
            "Failed to retrieve email address from Graph API response".to_string(),
            None,
        ))
}

    
    async fn fetch_access_control(
        &self,
        es_client: &Elasticsearch,
        email: &str,
    ) -> Result<Value, rmcp::Error> {
        // Construire la requête pour GSEDOCSACL
        let acl_request = json!({
            "params": {
                "query_string": email,
                "default_field": "_id"
            }
        });
        println!("ACL request: {}", acl_request); // Debug log

        // Envoyer la requête à GSEDOCSACL
        let acl_response = es_client
            .transport()
            .send(
                elasticsearch::http::Method::Post,
                "/_application/search_application/GSEDOCSACL/_search",
                http::HeaderMap::new(),
                None::<&()>,
                Some(elasticsearch::http::request::JsonBody::new(acl_request)),
                None,
            )
            .await;

        // Lire la réponse JSON
        let acl_data: Value = read_json(acl_response).await?;

        // Extraire le champ `access_control`
        acl_data
            .get("hits")
            .and_then(|hits| hits.get("hits"))
            .and_then(|hits_array| hits_array.as_array())
            .and_then(|array| array.first())
            .and_then(|first_hit| first_hit.get("_source"))
            .and_then(|source| source.get("query"))
            .and_then(|query| query.get("template"))
            .and_then(|template| template.get("params"))
            .and_then(|params| params.get("access_control"))
            .cloned()
            .ok_or_else(|| rmcp::Error::new(
                ErrorCode::INTERNAL_ERROR,
                "Failed to retrieve access_control from GSEDOCSACL response".to_string(),
                None,
            ))
    }


    //---------------------------------------------------------------------------------------------
    /// Tool: list indices
    /*
    #[tool(
        description = "List all available Elasticsearch indices",
        annotations(title = "List ES indices", read_only_hint = true)
    )]
    async fn list_indices(
        &self,
        req_ctx: RequestContext<RoleServer>,
        Parameters(ListIndicesParams { index_pattern }): Parameters<ListIndicesParams>,
    ) -> Result<CallToolResult, rmcp::Error> {
        let es_client = self.es_client.get(req_ctx);
        let response = es_client
            .cat()
            .indices(CatIndicesParts::Index(&[&index_pattern]))
            .h(&["index", "status", "docs.count"])
            .format("json")
            .send()
            .await;

        let response: Vec<CatIndexResponse> = read_json(response).await?;

        Ok(CallToolResult::success(vec![
            Content::text(format!("Found {} indices:", response.len())),
            Content::json(response)?,
        ]))
    }
    */
    //---------------------------------------------------------------------------------------------
    /// Tool: get mappings for an index
    /*
    #[tool(
        description = "Get field mappings for a specific Elasticsearch index",
        annotations(title = "Get ES index mappings", read_only_hint = true)
    )]
    async fn get_mappings(
        &self,
        req_ctx: RequestContext<RoleServer>,
        Parameters(GetMappingsParams { index }): Parameters<GetMappingsParams>,
    ) -> Result<CallToolResult, rmcp::Error> {
        let es_client = self.es_client.get(req_ctx);
        let response = es_client
            .indices()
            .get_mapping(IndicesGetMappingParts::Index(&[&index]))
            .send()
            .await;

        let response: MappingResponse = read_json(response).await?;

        // use the first mapping (we can have many if the name is a wildcard)
        let mapping = response.values().next().unwrap();

        Ok(CallToolResult::success(vec![
            Content::text(format!("Mappings for index {index}:")),
            Content::json(mapping)?,
        ]))
    }
    */
    //---------------------------------------------------------------------------------------------
    /// Tool: search an index with the Query DSL
    ///
    /// The additional 'fields' parameter helps some LLMs that don't know about the `_source`
    /// request property to narrow down the data returned and reduce their context size
    /*
    #[tool(
        description = "Perform an Elasticsearch search with the provided query DSL.",
        annotations(title = "Elasticsearch search DSL query", read_only_hint = true)
    )]
    async fn search(
        &self,
        req_ctx: RequestContext<RoleServer>,
        Parameters(SearchParams {
            index,
            fields,
            query_body,
        }): Parameters<SearchParams>,
    ) -> Result<CallToolResult, rmcp::Error> {
        let es_client = self.es_client.get(req_ctx);

        let mut query_body = query_body;

        if let Some(fields) = fields {
            // Augment _source if it exists
            if let Some(Value::Array(values)) = query_body.get_mut("_source") {
                for field in fields.into_iter() {
                    values.push(Value::String(field))
                }
            } else {
                query_body.insert("_source".to_string(), json!(fields));
            }
        }

        let response = es_client
            .search(SearchParts::Index(&[&index]))
            .body(query_body)
            .send()
            .await;

        let response: SearchResult = read_json(response).await?;

        let mut results: Vec<Content> = Vec::new();

        // Send result stats only if it's not pure aggregation results
        if response.aggregations.is_empty() || !response.hits.hits.is_empty() {
            let total = response
                .hits
                .total
                .map(|t| t.value.to_string())
                .unwrap_or("unknown".to_string());

            results.push(Content::text(format!(
                "Total results: {}, showing {}.",
                total,
                response.hits.hits.len()
            )));
        }

        // Original prototype sent a separate content for each document, it seems to confuse some LLMs
        // for hit in &response.hits.hits {
        //     results.push(Content::json(&hit.source)?);
        // }
        if !response.hits.hits.is_empty() {
            let sources = response.hits.hits.iter().map(|hit| &hit.source).collect::<Vec<_>>();
            results.push(Content::json(&sources)?);
        }

        if !response.aggregations.is_empty() {
            results.push(Content::text("Aggregations results:"));
            results.push(Content::json(&response.aggregations)?);
        }

        Ok(CallToolResult::success(results))
    }
    */
    //---------------------------------------------------------------------------------------------
    /// Tool: ES|QL
    /*
    #[tool(
        description = "Perform an Elasticsearch ES|QL query.",
        annotations(title = "Elasticsearch ES|QL query", read_only_hint = true)
    )]
    async fn esql(
        &self,
        req_ctx: RequestContext<RoleServer>,
        Parameters(EsqlQueryParams { query }): Parameters<EsqlQueryParams>,
    ) -> Result<CallToolResult, rmcp::Error> {
        let es_client = self.es_client.get(req_ctx);

        let request = EsqlQueryRequest { query };

        let response = es_client.esql().query().body(request).send().await;
        let response: EsqlQueryResponse = read_json(response).await?;

        // Transform response into an array of objects
        let mut objects: Vec<Value> = Vec::new();
        for row in response.values.into_iter() {
            let mut obj = Map::new();
            for (i, value) in row.into_iter().enumerate() {
                obj.insert(response.columns[i].name.clone(), value);
            }
            objects.push(Value::Object(obj));
        }

        Ok(CallToolResult::success(vec![
            Content::text("Results"),
            Content::json(objects)?,
        ]))
    }
    */
    //---------------------------------------------------------------------------------------------
    // Tool: get shard information
    /*
    #[tool(
        description = "Get shard information for all or specific indices.",
        annotations(title = "Get ES shard information", read_only_hint = true)
    )]
    async fn get_shards(
        &self,
        req_ctx: RequestContext<RoleServer>,
        Parameters(GetShardsParams { index }): Parameters<GetShardsParams>,
    ) -> Result<CallToolResult, rmcp::Error> {
        let es_client = self.es_client.get(req_ctx);

        let indices: [&str; 1];
        let parts = match &index {
            Some(index) => {
                indices = [index];
                CatShardsParts::Index(&indices)
            }
            None => CatShardsParts::None,
        };
        let response = es_client
            .cat()
            .shards(parts)
            .format("json")
            .h(&["index", "shard", "prirep", "state", "docs", "store", "node"])
            .send()
            .await;

        let response: Vec<CatShardsResponse> = read_json(response).await?;

        Ok(CallToolResult::success(vec![
            Content::text(format!("Found {} shards:", response.len())),
            Content::json(response)?,
        ]))
    }
    */
    /// Tool: debug headers
    /*
    #[tool(
        description = "Retourne les entêtes visibles côté serveur (si transmis par le proxy).",
        annotations(title = "Debug headers", read_only_hint = true)
    )]
    async fn debug_headers(
        &self,
        req_ctx: RequestContext<RoleServer>,
        Parameters(DebugHeadersParams {}): Parameters<DebugHeadersParams>,
    ) -> Result<CallToolResult, rmcp::Error> {
        use http::request::Parts;
        use serde_json::{Map, Value};

        let headers_json = req_ctx
            .extensions
            .get::<Parts>()
            .map(|p| {
                let mut map = Map::new();
                for (name, value) in p.headers.iter() {
                    let v = value
                        .to_str()
                        .map(|s| Value::String(s.to_string()))
                        .unwrap_or_else(|_| Value::String(String::from("[non-UTF8]")));
                    map.insert(name.as_str().to_string(), v);
                }
                Value::Object(map)
            })
            .unwrap_or(Value::Null);

        let body = json!({ "headers": headers_json });
        Ok(CallToolResult::success(vec![
            Content::text(serde_json::to_string_pretty(&body).unwrap()),
        ]))
    }
    */
    //---------------------------------------------------------------------------------------------
    /// Tool: search the GSE document library
    #[tool(
        description = "Search the GSE document library with a content search and get the documents contents, names and urls.",
        annotations(title = "Search GSE Document Library", read_only_hint = false)
    )]
    async fn searchgsedocumentlibrary(
        &self,
        req_ctx: RequestContext<RoleServer>,
        Parameters(SearchGseDocumentLibraryParams { user_query }): Parameters<SearchGseDocumentLibraryParams>,
    ) -> Result<CallToolResult, rmcp::Error> {
        // Step 1: Retrieve the bearer token from the request context
        let token = Self::extract_bearer_token(&req_ctx)?;
        // Step 2: Fetch the user's email address
        let email = Self::fetch_user_email(token).await?;

        let es_client = self.es_client.get(req_ctx);

        let access_control = self.fetch_access_control(&es_client, &email).await?;
        // Step 4: Query the GSEDOCS search application
        let gsedocs_request = json!({
            "params": {
                "size": 5,
                "query_name": "",
                "query_content": user_query,
                "semantic_field": "semantic_text",
                "name_field": "name",
                "search_content": true,
                "search_name": false,
                "number_of_fragments": 3,
                "content_boost": 1.0,
                "highlight_name": true,
                "require_name_filter": false,
                "minimum_should_match": 1,
                "min_score": 0.0,
                "access_control": access_control
            }
        });
        println!("GSEDOCS request: {}", gsedocs_request); // Debug log

        let gsedocs_response = es_client
            .transport()
            .send(
                elasticsearch::http::Method::Post,
                "/_application/search_application/GSEDOCS/_search",
                http::HeaderMap::new(),
                None::<&()>,
                Some(elasticsearch::http::request::JsonBody::new(gsedocs_request)),
                None,
            )
            .await;
        
        let gsedocs_data: Value = read_json(gsedocs_response).await?;
        println!("GSEDOCS response: {}", gsedocs_data); // Debug log
        // Step 5: Extract results and highlights
        let results = gsedocs_data
            .get("hits")
            .and_then(|hits| hits.get("hits"))
            .ok_or_else(|| rmcp::Error::new(
                ErrorCode::INTERNAL_ERROR, // Internal error
                "Failed to retrieve hits from GSEDOCS response".to_string(),
                None,
            ))?;

        let highlights = gsedocs_data
            .get("hits")
            .and_then(|hits| hits.get("hits"))
            .and_then(|hits_array| hits_array.as_array())
            .map(|array| {
                array
                    .iter()
                    .filter_map(|hit| hit.get("highlight"))
                    .collect::<Vec<_>>()
            })
            .ok_or_else(|| rmcp::Error::new(
                ErrorCode::INTERNAL_ERROR,
                "Failed to retrieve highlights from GSEDOCS response".to_string(),
                None,
            ))?;

        // Step 6: Return the results and highlights
        Ok(CallToolResult::success(vec![
            Content::text("Search results:"),
            Content::json(results)?,
            Content::text("Highlights:"),
            Content::json(highlights)?,
        ]))
    }

    /// Tool: Get project ID by name
#[tool(
    description = "Retrieve the ID of a project based on its name or number.",
    annotations(title = "Get Project ID", read_only_hint = true)
)]
async fn get_project_id(
    &self,
    req_ctx: RequestContext<RoleServer>,
    Parameters(SearchGseDocumentLibraryParams { user_query }): Parameters<SearchGseDocumentLibraryParams>,
) -> Result<CallToolResult, rmcp::Error> {
    // Step 1: Retrieve the bearer token from the request context
    let token = Self::extract_bearer_token(&req_ctx)?;
    let email = Self::fetch_user_email(token).await?;
    let es_client = self.es_client.get(req_ctx);
    let access_control = self.fetch_access_control(&es_client, &email).await?;

    // Step 2: Build the Elasticsearch query
    let search_request = json!({
        "query": {
            "bool": {
                "must": [
                    { "term": { "object_type": "site" } },
                    { "match": { "name": user_query } }
                ]
            }
        },
        "size": 1 // Limit to one result
    });
    println!("Search request: {}", search_request); // Debug log

    // Step 3: Send the query to Elasticsearch
    let search_response = es_client
        .transport()
        .send(
            elasticsearch::http::Method::Post,
            "/_application/search_application/GSEDOCS/_search", // Adjust the endpoint if necessary
            http::HeaderMap::new(),
            None::<&()>,
            Some(elasticsearch::http::request::JsonBody::new(search_request)),
            None,
        )
        .await;

    let search_data: Value = read_json(search_response).await?;
    println!("Search response: {}", search_data); // Debug log

    // Step 4: Extract the project ID
    let project_id = search_data
        .get("hits")
        .and_then(|hits| hits.get("hits"))
        .and_then(|hits_array| hits_array.as_array())
        .and_then(|array| array.first())
        .and_then(|first_hit| first_hit.get("_source"))
        .and_then(|source| source.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| rmcp::Error::new(
            ErrorCode::INTERNAL_ERROR,
            "Failed to retrieve project ID from search response".to_string(),
            None,
        ))?;

    // Step 5: Return the project ID
    Ok(CallToolResult::success(vec![
        Content::text(format!("Project ID: {}", project_id)),
    ]))
}
/// Tool: Get documents by matching a term, optionally filtered by siteId
#[tool(
    description = "Retrieve a list of documents matching a term, optionally filtered by a specific siteId.",
    annotations(title = "Get Documents", read_only_hint = true)
)]
async fn get_documents(
    &self,
    req_ctx: RequestContext<RoleServer>,
    Parameters(GetDocumentsParams { query, site_id }): Parameters<GetDocumentsParams>,
) -> Result<CallToolResult, rmcp::Error> {
    let token = Self::extract_bearer_token(&req_ctx)?;
    let email = Self::fetch_user_email(token).await?;
    let es_client = self.es_client.get(req_ctx);
    let access_control = self.fetch_access_control(&es_client, &email).await?;

    let mut params = json!({
            "query_name": query,
            "name_field": "name",
            "search_name": true, // Enable search by name
            "search_content": false,
            "access_control": access_control
        });

        // Add siteId filter if provided
        if let Some(site_id) = site_id {
            params["parentReference.siteId"] = json!(site_id);
        }

        let search_request = json!({ "params": params });
        println!("Search request: {}", search_request); // Debug log

        // Step 3: Send the query to Elasticsearch
    let search_response = es_client
        .transport()
        .send(
            elasticsearch::http::Method::Post,
            "/_application/search_application/GSEDOCS/_search", // Adjust the endpoint if necessary
            http::HeaderMap::new(),
            None::<&()>,
            Some(elasticsearch::http::request::JsonBody::new(search_request)),
            None,
        )
        .await;

    let search_data: Value = read_json(search_response).await?;
    println!("Search response: {}", search_data); // Debug log

    // Step 4: Extract the list of documents
    let total_documents = search_data
        .get("hits")
        .and_then(|hits| hits.get("total"))
        .and_then(|total| total.get("value"))
        .and_then(Value::as_u64)
        .ok_or_else(|| rmcp::Error::new(
            ErrorCode::INTERNAL_ERROR,
            "Failed to retrieve total document count from search response".to_string(),
            None,
        ))?;

    let documents = search_data
        .get("hits")
        .and_then(|hits| hits.get("hits"))
        .and_then(|hits_array| hits_array.as_array())
        .map(|array| {
            array
                .iter()
                .filter_map(|hit| {
                    let name = hit
                        .get("_source")
                        .and_then(|source| source.get("name"))
                        .and_then(Value::as_str)
                        .map(String::from);

                    let web_url = hit
                        .get("_source")
                        .and_then(|source| source.get("webUrl"))
                        .and_then(Value::as_str)
                        .map(String::from);

                    match (name, web_url) {
                        (Some(name), Some(web_url)) => Some(json!({ "name": name, "webUrl": web_url })),
                        _ => None,
                    }
                })
                .collect::<Vec<_>>()
        })
        .ok_or_else(|| rmcp::Error::new(
            ErrorCode::INTERNAL_ERROR,
            "Failed to retrieve documents from search response".to_string(),
            None,
        ))?;

    // Step 5: Return the list of documents
    Ok(CallToolResult::success(vec![
        Content::text(format!("Total documents matching the query: {}", total_documents)),
        Content::json(documents)?,
    ]))
}

}

#[tool_handler]
impl ServerHandler for EsBaseTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_03_26,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("Provides access to Elasticsearch".to_string()),
        }
    }
}

//-------------------------------------------------------------------------------------------------
// Type definitions for ES request/responses (the Rust client doesn't have them yet) and tool responses.

//----- Search request

#[derive(Serialize, Deserialize)]
pub struct SearchResult {
    pub hits: Hits,
    #[serde(default)]
    pub aggregations: IndexMap<String, Value>,
}

#[derive(Serialize, Deserialize)]
pub struct Hits {
    pub total: Option<TotalHits>,
    pub hits: Vec<Hit>,
}

#[derive(Serialize, Deserialize)]
pub struct TotalHits {
    pub value: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Hit {
    #[serde(rename = "_source")]
    pub source: Value,
}

//----- Cat responses

#[derive(Serialize, Deserialize)]
pub struct CatIndexResponse {
    pub index: String,
    pub status: String,
    #[serde(rename = "docs.count", deserialize_with = "deserialize_number_from_string")]
    pub doc_count: u64,
}

#[derive(Serialize, Deserialize)]
pub struct CatShardsResponse {
    pub index: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub shard: usize,
    pub prirep: String,
    pub state: String,
    #[serde(deserialize_with = "deserialize_option_number_from_string")]
    pub docs: Option<u64>,
    pub store: Option<String>,
    pub node: Option<String>,
}

//----- Index mappings

pub type MappingResponse = HashMap<String, Mappings>;

#[derive(Serialize, Deserialize)]
pub struct Mappings {
    pub mappings: Mapping,
}

#[derive(Serialize, Deserialize)]
pub struct Mapping {
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonObject>,
    properties: HashMap<String, MappingProperty>,
}

#[derive(Serialize, Deserialize)]
pub struct MappingProperty {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub settings: HashMap<String, serde_json::Value>,
}

//----- ES|QL

#[derive(Serialize, Deserialize)]
pub struct EsqlQueryRequest {
    pub query: String,
}

#[derive(Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Serialize, Deserialize)]
pub struct EsqlQueryResponse {
    pub is_partial: Option<bool>,
    pub columns: Vec<Column>,
    pub values: Vec<Vec<Value>>,
}
