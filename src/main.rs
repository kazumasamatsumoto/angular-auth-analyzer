use clap::{App, Arg, SubCommand};
use serde_json;
use serde_yaml;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use regex::Regex;

#[derive(Debug, Serialize, Deserialize)]
struct AuthAnalysis {
    guards: Vec<GuardInfo>,
    services: Vec<ServiceInfo>,
    components: Vec<ComponentInfo>,
    interceptors: Vec<InterceptorInfo>,
    routes: Vec<RouteInfo>,
    potential_issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GuardInfo {
    name: String,
    file_path: String,
    guard_type: String, // CanActivate, CanLoad, etc.
    dependencies: Vec<String>,
    auth_check_methods: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServiceInfo {
    name: String,
    file_path: String,
    auth_methods: Vec<String>,
    token_storage: Vec<String>,
    api_endpoints: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ComponentInfo {
    name: String,
    file_path: String,
    auth_related_methods: Vec<String>,
    protected_sections: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InterceptorInfo {
    name: String,
    file_path: String,
    token_injection: bool,
    error_handling: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RouteInfo {
    path: String,
    component: String,
    guards: Vec<String>,
    lazy_loaded: bool,
}

fn main() {
    let matches = App::new("Angular Auth Analyzer")
        .version("1.0")
        .author("Your Name")
        .about("Analyzes Angular applications for authentication implementation")
        .arg(
            Arg::with_name("path")
                .short("p")
                .long("path")
                .value_name("PATH")
                .help("Path to Angular project root")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("OUTPUT")
                .help("Output format (json, yaml, table)")
                .takes_value(true)
                .default_value("table"),
        )
        .arg(
            Arg::with_name("detailed")
                .short("d")
                .long("detailed")
                .help("Show detailed analysis including code snippets"),
        )
        .subcommand(
            SubCommand::with_name("guards")
                .about("Analyze authentication guards only"),
        )
        .subcommand(
            SubCommand::with_name("services")
                .about("Analyze authentication services only"),
        )
        .subcommand(
            SubCommand::with_name("routes")
                .about("Analyze protected routes only"),
        )
        .subcommand(
            SubCommand::with_name("security")
                .about("Perform security analysis"),
        )
        .get_matches();

    let project_path = matches.value_of("path").unwrap();
    let output_format = matches.value_of("output").unwrap();
    let detailed = matches.is_present("detailed");

    let analyzer = AngularAuthAnalyzer::new(project_path);
    
    match matches.subcommand() {
        ("guards", _) => {
            let guards = analyzer.analyze_guards();
            output_guards(&guards, output_format, detailed);
        }
        ("services", _) => {
            let services = analyzer.analyze_services();
            output_services(&services, output_format, detailed);
        }
        ("routes", _) => {
            let routes = analyzer.analyze_routes();
            output_routes(&routes, output_format, detailed);
        }
        ("security", _) => {
            let issues = analyzer.security_analysis();
            output_security_issues(&issues, output_format);
        }
        _ => {
            let analysis = analyzer.full_analysis();
            output_full_analysis(&analysis, output_format, detailed);
        }
    }
}

struct AngularAuthAnalyzer {
    project_path: String,
}

impl AngularAuthAnalyzer {
    fn new(path: &str) -> Self {
        Self {
            project_path: path.to_string(),
        }
    }

    fn full_analysis(&self) -> AuthAnalysis {
        AuthAnalysis {
            guards: self.analyze_guards(),
            services: self.analyze_services(),
            components: self.analyze_components(),
            interceptors: self.analyze_interceptors(),
            routes: self.analyze_routes(),
            potential_issues: self.security_analysis(),
        }
    }

    fn analyze_guards(&self) -> Vec<GuardInfo> {
        let mut guards = Vec::new();
        
        for entry in WalkDir::new(&self.project_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if let Some(extension) = entry.path().extension() {
                if extension == "ts" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if self.is_guard_file(&content) {
                            guards.push(self.extract_guard_info(entry.path(), &content));
                        }
                    }
                }
            }
        }
        
        guards
    }

    fn analyze_services(&self) -> Vec<ServiceInfo> {
        let mut services = Vec::new();
        
        for entry in WalkDir::new(&self.project_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if let Some(extension) = entry.path().extension() {
                if extension == "ts" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if self.is_auth_service(&content) {
                            services.push(self.extract_service_info(entry.path(), &content));
                        }
                    }
                }
            }
        }
        
        services
    }

    fn analyze_components(&self) -> Vec<ComponentInfo> {
        let mut components = Vec::new();
        
        for entry in WalkDir::new(&self.project_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if let Some(extension) = entry.path().extension() {
                if extension == "ts" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if self.has_auth_logic(&content) {
                            components.push(self.extract_component_info(entry.path(), &content));
                        }
                    }
                }
            }
        }
        
        components
    }

    fn analyze_interceptors(&self) -> Vec<InterceptorInfo> {
        let mut interceptors = Vec::new();
        
        for entry in WalkDir::new(&self.project_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if let Some(extension) = entry.path().extension() {
                if extension == "ts" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if self.is_http_interceptor(&content) {
                            interceptors.push(self.extract_interceptor_info(entry.path(), &content));
                        }
                    }
                }
            }
        }
        
        interceptors
    }

    fn analyze_routes(&self) -> Vec<RouteInfo> {
        let mut routes = Vec::new();
        
        for entry in WalkDir::new(&self.project_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if let Some(extension) = entry.path().extension() {
                if extension == "ts" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if self.is_routing_file(&content) {
                            routes.extend(self.extract_route_info(&content));
                        }
                    }
                }
            }
        }
        
        routes
    }

    fn security_analysis(&self) -> Vec<String> {
        let mut issues = Vec::new();
        
        // JWT token storage analysis
        if self.check_insecure_token_storage() {
            issues.push("Potential insecure token storage detected (localStorage)".to_string());
        }
        
        // Missing CSRF protection
        if !self.check_csrf_protection() {
            issues.push("CSRF protection not detected".to_string());
        }
        
        // Hardcoded secrets
        if self.check_hardcoded_secrets() {
            issues.push("Potential hardcoded secrets detected".to_string());
        }
        
        // Unprotected routes
        let unprotected = self.find_unprotected_routes();
        if !unprotected.is_empty() {
            issues.push(format!("Unprotected routes found: {}", unprotected.join(", ")));
        }
        
        issues
    }

    // Helper methods for pattern detection
    fn is_guard_file(&self, content: &str) -> bool {
        content.contains("CanActivate") || 
        content.contains("CanLoad") || 
        content.contains("CanActivateChild")
    }

    fn is_auth_service(&self, content: &str) -> bool {
        content.contains("@Injectable") && 
        (content.contains("login") || 
         content.contains("authenticate") || 
         content.contains("token") ||
         content.contains("AuthService"))
    }

    fn has_auth_logic(&self, content: &str) -> bool {
        content.contains("@Component") && 
        (content.contains("login") || 
         content.contains("logout") || 
         content.contains("isAuthenticated"))
    }

    fn is_http_interceptor(&self, content: &str) -> bool {
        content.contains("HttpInterceptor") && content.contains("intercept")
    }

    fn is_routing_file(&self, content: &str) -> bool {
        content.contains("Routes") || content.contains("RouterModule")
    }

    fn extract_guard_info(&self, path: &Path, content: &str) -> GuardInfo {
        let name_regex = Regex::new(r"export class (\w+)Guard").unwrap();
        let name = name_regex
            .captures(content)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let guard_type = if content.contains("CanActivate") {
            "CanActivate"
        } else if content.contains("CanLoad") {
            "CanLoad"
        } else {
            "Unknown"
        }.to_string();

        GuardInfo {
            name,
            file_path: path.to_string_lossy().to_string(),
            guard_type,
            dependencies: self.extract_dependencies(content),
            auth_check_methods: self.extract_auth_methods(content),
        }
    }

    fn extract_service_info(&self, path: &Path, content: &str) -> ServiceInfo {
        let name_regex = Regex::new(r"export class (\w+)").unwrap();
        let name = name_regex
            .captures(content)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        ServiceInfo {
            name,
            file_path: path.to_string_lossy().to_string(),
            auth_methods: self.extract_auth_methods(content),
            token_storage: self.extract_token_storage_methods(content),
            api_endpoints: self.extract_api_endpoints(content),
        }
    }

    fn extract_component_info(&self, path: &Path, content: &str) -> ComponentInfo {
        let name_regex = Regex::new(r"export class (\w+)Component").unwrap();
        let name = name_regex
            .captures(content)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        ComponentInfo {
            name,
            file_path: path.to_string_lossy().to_string(),
            auth_related_methods: self.extract_auth_methods(content),
            protected_sections: self.extract_protected_sections(content),
        }
    }

    fn extract_interceptor_info(&self, path: &Path, content: &str) -> InterceptorInfo {
        let name_regex = Regex::new(r"export class (\w+)Interceptor").unwrap();
        let name = name_regex
            .captures(content)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        InterceptorInfo {
            name,
            file_path: path.to_string_lossy().to_string(),
            token_injection: content.contains("Authorization") || content.contains("Bearer"),
            error_handling: self.extract_error_handlers(content),
        }
    }

    fn extract_route_info(&self, _content: &str) -> Vec<RouteInfo> {
        // Simplified route extraction - in practice, this would need more sophisticated parsing
        // TODO: Implement proper route parsing from routing modules
        Vec::new()
    }

    fn extract_dependencies(&self, _content: &str) -> Vec<String> {
        let mut _deps: Vec<String> = Vec::new();
        // TODO: Implement constructor parameter parsing
        // let constructor_regex = Regex::new(r"constructor\([^)]*\)").unwrap();
        
        // if let Some(constructor_match) = constructor_regex.find(content) {
        //     let constructor_content = constructor_match.as_str();
        //     // Extract service dependencies from constructor parameters
        //     // This is a simplified implementation
        // }
        
        Vec::new()
    }

    fn extract_auth_methods(&self, content: &str) -> Vec<String> {
        let mut methods = Vec::new();
        let method_regex = Regex::new(r"(\w+)\s*\([^)]*\)\s*\{").unwrap();
        
        for cap in method_regex.captures_iter(content) {
            let method_name = cap.get(1).unwrap().as_str();
            if method_name.contains("login") || 
               method_name.contains("logout") || 
               method_name.contains("auth") ||
               method_name.contains("token") {
                methods.push(method_name.to_string());
            }
        }
        
        methods
    }

    fn extract_token_storage_methods(&self, content: &str) -> Vec<String> {
        let mut storage_methods = Vec::new();
        
        if content.contains("localStorage") {
            storage_methods.push("localStorage".to_string());
        }
        if content.contains("sessionStorage") {
            storage_methods.push("sessionStorage".to_string());
        }
        if content.contains("cookies") || content.contains("Cookie") {
            storage_methods.push("cookies".to_string());
        }
        
        storage_methods
    }

    fn extract_api_endpoints(&self, content: &str) -> Vec<String> {
        let mut endpoints = Vec::new();
        let url_regex = Regex::new(r#"['"`]([^'"`]*(?:api|auth)[^'"`]*)['"`]"#).unwrap();
        
        for cap in url_regex.captures_iter(content) {
            endpoints.push(cap.get(1).unwrap().as_str().to_string());
        }
        
        endpoints
    }

    fn extract_protected_sections(&self, content: &str) -> Vec<String> {
        let mut sections = Vec::new();
        
        if content.contains("*ngIf") && (content.contains("isAuthenticated") || content.contains("loggedIn")) {
            sections.push("Conditional rendering based on auth state".to_string());
        }
        
        sections
    }

    fn extract_error_handlers(&self, content: &str) -> Vec<String> {
        let mut handlers = Vec::new();
        
        if content.contains("catchError") {
            handlers.push("Error handling with catchError".to_string());
        }
        if content.contains("401") || content.contains("403") {
            handlers.push("HTTP auth error handling".to_string());
        }
        
        handlers
    }

    // Security analysis methods
    fn check_insecure_token_storage(&self) -> bool {
        for entry in WalkDir::new(&self.project_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if let Some(extension) = entry.path().extension() {
                if extension == "ts" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if content.contains("localStorage.setItem") && content.contains("token") {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn check_csrf_protection(&self) -> bool {
        // Check for CSRF token implementation
        for entry in WalkDir::new(&self.project_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if let Some(extension) = entry.path().extension() {
                if extension == "ts" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if content.contains("HttpClientXsrfModule") || content.contains("X-CSRF-TOKEN") {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn check_hardcoded_secrets(&self) -> bool {
        let secret_patterns = [
            r#"secret.*=.*["'][a-zA-Z0-9+/=]{20,}["']"#,
            r#"key.*=.*["'][a-zA-Z0-9+/=]{20,}["']"#,
            r#"password.*=.*["'][^"']+["']"#,
        ];
        
        for entry in WalkDir::new(&self.project_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if let Some(extension) = entry.path().extension() {
                if extension == "ts" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        for pattern in &secret_patterns {
                            let regex = Regex::new(pattern).unwrap();
                            if regex.is_match(&content) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn find_unprotected_routes(&self) -> Vec<String> {
        // This would analyze routing configuration to find routes without guards
        Vec::new()
    }
}

// Output formatting functions
fn output_guards(guards: &[GuardInfo], format: &str, detailed: bool) {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(guards).unwrap()),
        "yaml" => println!("{}", serde_yaml::to_string(guards).unwrap()),
        _ => {
            println!("╭─ Authentication Guards Analysis ─╮");
            for guard in guards {
                println!("│ Guard: {}", guard.name);
                println!("│ Type: {}", guard.guard_type);
                println!("│ File: {}", guard.file_path);
                if detailed {
                    println!("│ Dependencies: {:?}", guard.dependencies);
                    println!("│ Auth Methods: {:?}", guard.auth_check_methods);
                }
                println!("├─────────────────────────────────────");
            }
            println!("╰─────────────────────────────────────╯");
        }
    }
}

fn output_services(services: &[ServiceInfo], format: &str, detailed: bool) {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(services).unwrap()),
        "yaml" => println!("{}", serde_yaml::to_string(services).unwrap()),
        _ => {
            println!("╭─ Authentication Services Analysis ─╮");
            for service in services {
                println!("│ Service: {}", service.name);
                println!("│ File: {}", service.file_path);
                if detailed {
                    println!("│ Auth Methods: {:?}", service.auth_methods);
                    println!("│ Token Storage: {:?}", service.token_storage);
                    println!("│ API Endpoints: {:?}", service.api_endpoints);
                }
                println!("├─────────────────────────────────────");
            }
            println!("╰─────────────────────────────────────╯");
        }
    }
}

fn output_routes(routes: &[RouteInfo], format: &str, detailed: bool) {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(routes).unwrap()),
        "yaml" => println!("{}", serde_yaml::to_string(routes).unwrap()),
        _ => {
            println!("╭─ Protected Routes Analysis ─╮");
            for route in routes {
                println!("│ Path: {}", route.path);
                println!("│ Component: {}", route.component);
                println!("│ Guards: {:?}", route.guards);
                if detailed {
                    println!("│ Lazy Loaded: {}", route.lazy_loaded);
                }
                println!("├─────────────────────────────────────");
            }
            println!("╰─────────────────────────────────────╯");
        }
    }
}

fn output_security_issues(issues: &[String], format: &str) {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(issues).unwrap()),
        "yaml" => println!("{}", serde_yaml::to_string(issues).unwrap()),
        _ => {
            println!("╭─ Security Analysis Results ─╮");
            if issues.is_empty() {
                println!("│ [OK] No security issues detected!");
            } else {
                for (i, issue) in issues.iter().enumerate() {
                    println!("│ [WARN] {}: {}", i + 1, issue);
                }
            }
            println!("╰─────────────────────────────────────╯");
        }
    }
}

fn output_full_analysis(analysis: &AuthAnalysis, format: &str, detailed: bool) {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(analysis).unwrap()),
        "yaml" => println!("{}", serde_yaml::to_string(analysis).unwrap()),
        _ => {
            println!("╭─ Complete Authentication Analysis ─╮");
            println!("│ Guards found: {}", analysis.guards.len());
            println!("│ Services found: {}", analysis.services.len());
            println!("│ Components with auth: {}", analysis.components.len());
            println!("│ Interceptors found: {}", analysis.interceptors.len());
            println!("│ Protected routes: {}", analysis.routes.len());
            println!("│ Security issues: {}", analysis.potential_issues.len());
            println!("╰─────────────────────────────────────╯");
            
            if detailed {
                output_guards(&analysis.guards, "table", true);
                output_services(&analysis.services, "table", true);
                output_security_issues(&analysis.potential_issues, "table");
            }
        }
    }
}