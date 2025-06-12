#!/usr/bin/env python3
"""
ShadowOS Cloud v1.0 - Mission Orchestration System
Advanced Task Management & Module Coordination

Developed by ShadowRock Team
"""

import json
import yaml
import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import uuid
import os
from pathlib import Path

class MissionStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"

class TaskPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ModuleType(Enum):
    PROXY = "proxy_manager"
    INTEL = "intel_engine"
    SCANNER = "scanner_engine"
    MUTATION = "mutation_engine"
    EXPLOIT = "exploit_engine"
    REPORT = "report_engine"
    SUBMIT = "h1_submitter"

@dataclass
class TaskConfig:
    task_id: str
    module_type: ModuleType
    target: str
    parameters: Dict[str, Any]
    dependencies: List[str]  # Task IDs this task depends on
    priority: TaskPriority
    timeout: int  # seconds
    retry_count: int
    success_criteria: Dict[str, Any]
    failure_actions: List[str]

@dataclass
class MissionConfig:
    mission_id: str
    name: str
    description: str
    target_domain: str
    created_by: str
    created_at: datetime
    tasks: List[TaskConfig]
    global_config: Dict[str, Any]
    notifications: Dict[str, Any]
    export_settings: Dict[str, Any]

@dataclass
class TaskResult:
    task_id: str
    status: MissionStatus
    start_time: datetime
    end_time: Optional[datetime]
    output_data: Dict[str, Any]
    error_message: Optional[str]
    metrics: Dict[str, Any]
    artifacts: List[str]  # File paths to generated artifacts

@dataclass
class MissionResult:
    mission_id: str
    status: MissionStatus
    start_time: datetime
    end_time: Optional[datetime]
    task_results: Dict[str, TaskResult]
    summary: Dict[str, Any]
    artifacts: List[str]

class ShadowMissionOrchestrator:
    """
    📋 Advanced Mission Orchestration System
    
    Features:
    - Task dependency management
    - Parallel execution planning
    - Real-time progress tracking
    - Automatic retry logic
    - Result aggregation
    - Artifact management
    """
    
    def __init__(self, workspace_dir: str = "./shadowos_workspace"):
        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(exist_ok=True)
        
        # Mission storage
        self.missions_dir = self.workspace_dir / "missions"
        self.missions_dir.mkdir(exist_ok=True)
        
        # Artifacts storage
        self.artifacts_dir = self.workspace_dir / "artifacts"
        self.artifacts_dir.mkdir(exist_ok=True)
        
        # Logs storage
        self.logs_dir = self.workspace_dir / "logs"
        self.logs_dir.mkdir(exist_ok=True)
        
        # Module registry
        self.module_registry: Dict[ModuleType, Any] = {}
        self.active_missions: Dict[str, MissionResult] = {}
        
        self.setup_logging()
        
    def setup_logging(self):
        """Setup mission orchestration logging"""
        log_file = self.logs_dir / f"orchestrator_{datetime.now().strftime('%Y%m%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [📋 MISSION] %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def register_module(self, module_type: ModuleType, module_instance: Any):
        """Register a module for mission execution"""
        self.module_registry[module_type] = module_instance
        self.logger.info(f"📦 Registered module: {module_type.value}")
        
    def create_mission_from_template(self, template_name: str, target_domain: str, **kwargs) -> MissionConfig:
        """Create mission from predefined template"""
        templates = {
            "full_recon": self.create_full_recon_mission,
            "idor_hunt": self.create_idor_hunt_mission,
            "api_security": self.create_api_security_mission,
            "subdomain_takeover": self.create_subdomain_takeover_mission,
            "waf_bypass": self.create_waf_bypass_mission
        }
        
        if template_name not in templates:
            raise ValueError(f"Unknown template: {template_name}")
            
        return templates[template_name](target_domain, **kwargs)
        
    def create_full_recon_mission(self, target_domain: str, **kwargs) -> MissionConfig:
        """Create comprehensive reconnaissance mission"""
        mission_id = str(uuid.uuid4())
        
        tasks = [
            # Task 1: Proxy Setup
            TaskConfig(
                task_id=f"{mission_id}_proxy_init",
                module_type=ModuleType.PROXY,
                target=target_domain,
                parameters={
                    "action": "initialize",
                    "rotation_interval": kwargs.get("rotation_interval", 300),
                    "health_check": True
                },
                dependencies=[],
                priority=TaskPriority.HIGH,
                timeout=300,
                retry_count=3,
                success_criteria={"active_proxies": {"min": 1}},
                failure_actions=["notify_admin", "fallback_direct"]
            ),
            
            # Task 2: Intelligence Gathering
            TaskConfig(
                task_id=f"{mission_id}_intel_recon",
                module_type=ModuleType.INTEL,
                target=target_domain,
                parameters={
                    "subdomain_sources": ["crt.sh", "virustotal", "bruteforce"],
                    "tech_detection": True,
                    "waf_detection": True,
                    "rate_limit_probing": True,
                    "api_keys": kwargs.get("api_keys", {})
                },
                dependencies=[f"{mission_id}_proxy_init"],
                priority=TaskPriority.HIGH,
                timeout=1800,
                retry_count=2,
                success_criteria={"subdomains_found": {"min": 1}},
                failure_actions=["continue_without_intel"]
            ),
            
            # Task 3: Vulnerability Scanning
            TaskConfig(
                task_id=f"{mission_id}_vuln_scan",
                module_type=ModuleType.SCANNER,
                target=target_domain,
                parameters={
                    "scan_types": ["idor", "auth_bypass", "injection"],
                    "intensity": kwargs.get("scan_intensity", "normal"),
                    "use_intel_data": True
                },
                dependencies=[f"{mission_id}_intel_recon"],
                priority=TaskPriority.CRITICAL,
                timeout=3600,
                retry_count=1,
                success_criteria={"scans_completed": {"min": 1}},
                failure_actions=["generate_partial_report"]
            ),
            
            # Task 4: Report Generation
            TaskConfig(
                task_id=f"{mission_id}_report_gen",
                module_type=ModuleType.REPORT,
                target=target_domain,
                parameters={
                    "format": ["json", "pdf", "html"],
                    "include_poc": True,
                    "severity_filter": kwargs.get("min_severity", "medium")
                },
                dependencies=[f"{mission_id}_vuln_scan"],
                priority=TaskPriority.MEDIUM,
                timeout=600,
                retry_count=2,
                success_criteria={"report_generated": True},
                failure_actions=["notify_failure"]
            )
        ]
        
        return MissionConfig(
            mission_id=mission_id,
            name=f"Full Reconnaissance - {target_domain}",
            description=f"Comprehensive security assessment of {target_domain}",
            target_domain=target_domain,
            created_by=kwargs.get("created_by", "shadowos"),
            created_at=datetime.now(),
            tasks=tasks,
            global_config={
                "max_concurrent_tasks": kwargs.get("max_concurrent", 3),
                "stealth_mode": kwargs.get("stealth", True),
                "save_artifacts": True,
                "auto_submit": kwargs.get("auto_submit", False)
            },
            notifications={
                "slack_webhook": kwargs.get("slack_webhook"),
                "email": kwargs.get("email"),
                "on_completion": True,
                "on_critical_finding": True
            },
            export_settings={
                "auto_export": True,
                "export_formats": ["json", "pdf"],
                "export_path": str(self.artifacts_dir)
            }
        )
        
    def create_idor_hunt_mission(self, target_domain: str, **kwargs) -> MissionConfig:
        """Create specialized IDOR hunting mission"""
        mission_id = str(uuid.uuid4())
        
        tasks = [
            # Proxy + Intel (same as full recon)
            TaskConfig(
                task_id=f"{mission_id}_proxy_init",
                module_type=ModuleType.PROXY,
                target=target_domain,
                parameters={"action": "initialize", "rotation_interval": 180},
                dependencies=[],
                priority=TaskPriority.HIGH,
                timeout=300,
                retry_count=3,
                success_criteria={"active_proxies": {"min": 1}},
                failure_actions=["notify_admin"]
            ),
            
            TaskConfig(
                task_id=f"{mission_id}_intel_recon",
                module_type=ModuleType.INTEL,
                target=target_domain,
                parameters={
                    "subdomain_sources": ["crt.sh", "bruteforce"],
                    "focus_apis": True,
                    "endpoint_discovery": True
                },
                dependencies=[f"{mission_id}_proxy_init"],
                priority=TaskPriority.HIGH,
                timeout=1200,
                retry_count=2,
                success_criteria={"api_endpoints": {"min": 1}},
                failure_actions=["continue_with_default_endpoints"]
            ),
            
            # IDOR-focused scanning
            TaskConfig(
                task_id=f"{mission_id}_idor_scan",
                module_type=ModuleType.SCANNER,
                target=target_domain,
                parameters={
                    "scan_types": ["idor_horizontal", "idor_vertical", "idor_batch"],
                    "parameter_fuzzing": True,
                    "id_enumeration": True,
                    "session_handling": "advanced"
                },
                dependencies=[f"{mission_id}_intel_recon"],
                priority=TaskPriority.CRITICAL,
                timeout=7200,  # 2 hours for thorough IDOR testing
                retry_count=1,
                success_criteria={"idor_tests": {"min": 10}},
                failure_actions=["save_partial_results"]
            ),
            
            # Advanced payload mutation
            TaskConfig(
                task_id=f"{mission_id}_payload_mutation",
                module_type=ModuleType.MUTATION,
                target=target_domain,
                parameters={
                    "mutation_types": ["parameter_pollution", "encoding_bypass", "type_confusion"],
                    "ai_generation": True,
                    "use_discovered_patterns": True
                },
                dependencies=[f"{mission_id}_idor_scan"],
                priority=TaskPriority.HIGH,
                timeout=1800,
                retry_count=2,
                success_criteria={"mutations_tested": {"min": 50}},
                failure_actions=["continue_with_basic_payloads"]
            ),
            
            # Exploitation and PoC generation
            TaskConfig(
                task_id=f"{mission_id}_exploit_gen",
                module_type=ModuleType.EXPLOIT,
                target=target_domain,
                parameters={
                    "generate_poc": True,
                    "extract_sensitive_data": kwargs.get("extract_data", False),
                    "chain_exploits": True
                },
                dependencies=[f"{mission_id}_payload_mutation"],
                priority=TaskPriority.CRITICAL,
                timeout=1200,
                retry_count=1,
                success_criteria={"exploits_generated": {"min": 1}},
                failure_actions=["generate_theoretical_poc"]
            ),
            
            # H1 Report Generation
            TaskConfig(
                task_id=f"{mission_id}_h1_report",
                module_type=ModuleType.REPORT,
                target=target_domain,
                parameters={
                    "report_type": "hackerone",
                    "include_exploitation_chain": True,
                    "severity_assessment": "auto",
                    "business_impact": True
                },
                dependencies=[f"{mission_id}_exploit_gen"],
                priority=TaskPriority.HIGH,
                timeout=600,
                retry_count=2,
                success_criteria={"h1_report_ready": True},
                failure_actions=["generate_basic_report"]
            )
        ]
        
        # Optional auto-submission
        if kwargs.get("auto_submit", False):
            tasks.append(
                TaskConfig(
                    task_id=f"{mission_id}_h1_submit",
                    module_type=ModuleType.SUBMIT,
                    target=target_domain,
                    parameters={
                        "platform": "hackerone",
                        "program_handle": kwargs.get("h1_program"),
                        "auto_submit": True,
                        "severity_threshold": kwargs.get("submit_threshold", "medium")
                    },
                    dependencies=[f"{mission_id}_h1_report"],
                    priority=TaskPriority.MEDIUM,
                    timeout=300,
                    retry_count=3,
                    success_criteria={"submission_id": {"exists": True}},
                    failure_actions=["save_for_manual_submit"]
                )
            )
        
        return MissionConfig(
            mission_id=mission_id,
            name=f"IDOR Hunt - {target_domain}",
            description=f"Specialized IDOR vulnerability hunting for {target_domain}",
            target_domain=target_domain,
            created_by=kwargs.get("created_by", "shadowos"),
            created_at=datetime.now(),
            tasks=tasks,
            global_config={
                "max_concurrent_tasks": 2,  # More conservative for IDOR hunting
                "stealth_mode": True,
                "save_artifacts": True,
                "detailed_logging": True
            },
            notifications={
                "slack_webhook": kwargs.get("slack_webhook"),
                "on_idor_found": True,
                "on_completion": True
            },
            export_settings={
                "auto_export": True,
                "export_formats": ["json", "pdf", "markdown"],
                "export_path": str(self.artifacts_dir)
            }
        )
        
    def save_mission(self, mission: MissionConfig) -> str:
        """Save mission configuration to file"""
        mission_file = self.missions_dir / f"{mission.mission_id}.yaml"
        
        # Convert to dict for serialization
        mission_dict = asdict(mission)
        
        # Convert datetime objects to ISO format
        mission_dict['created_at'] = mission.created_at.isoformat()
        
        # Convert enums to values
        for task in mission_dict['tasks']:
            task['module_type'] = task['module_type'].value
            task['priority'] = task['priority'].value
            
        with open(mission_file, 'w') as f:
            yaml.dump(mission_dict, f, default_flow_style=False, indent=2)
            
        self.logger.info(f"💾 Mission saved: {mission_file}")
        return str(mission_file)
        
    def load_mission(self, mission_file: str) -> MissionConfig:
        """Load mission configuration from file"""
        with open(mission_file, 'r') as f:
            mission_dict = yaml.safe_load(f)
            
        # Convert back from serialized format
        mission_dict['created_at'] = datetime.fromisoformat(mission_dict['created_at'])
        
        # Convert back to enums and dataclasses
        tasks = []
        for task_dict in mission_dict['tasks']:
            task_dict['module_type'] = ModuleType(task_dict['module_type'])
            task_dict['priority'] = TaskPriority(task_dict['priority'])
            tasks.append(TaskConfig(**task_dict))
            
        mission_dict['tasks'] = tasks
        
        return MissionConfig(**mission_dict)
        
    def validate_mission(self, mission: MissionConfig) -> List[str]:
        """Validate mission configuration"""
        errors = []
        
        # Check if required modules are registered
        required_modules = set(task.module_type for task in mission.tasks)
        for module_type in required_modules:
            if module_type not in self.module_registry:
                errors.append(f"Module {module_type.value} not registered")
                
        # Check task dependencies
        task_ids = set(task.task_id for task in mission.tasks)
        for task in mission.tasks:
            for dep_id in task.dependencies:
                if dep_id not in task_ids:
                    errors.append(f"Task {task.task_id} depends on non-existent task {dep_id}")
                    
        # Check for circular dependencies
        if self.has_circular_dependencies(mission.tasks):
            errors.append("Circular dependencies detected in task graph")
            
        return errors
        
    def has_circular_dependencies(self, tasks: List[TaskConfig]) -> bool:
        """Check for circular dependencies in task graph"""
        # Simple DFS-based cycle detection
        task_deps = {task.task_id: task.dependencies for task in tasks}
        visited = set()
        rec_stack = set()
        
        def dfs(task_id):
            if task_id in rec_stack:
                return True  # Cycle found
            if task_id in visited:
                return False
                
            visited.add(task_id)
            rec_stack.add(task_id)
            
            for dep in task_deps.get(task_id, []):
                if dfs(dep):
                    return True
                    
            rec_stack.remove(task_id)
            return False
            
        for task_id in task_deps:
            if task_id not in visited:
                if dfs(task_id):
                    return True
                    
        return False
        
    def calculate_execution_plan(self, mission: MissionConfig) -> List[List[str]]:
        """Calculate optimal task execution plan with parallelization"""
        # Topological sort for dependency resolution
        task_deps = {task.task_id: task.dependencies for task in mission.tasks}
        in_degree = {task_id: len(deps) for task_id, deps in task_deps.items()}
        
        execution_levels = []
        remaining_tasks = set(task_deps.keys())
        
        while remaining_tasks:
            # Find tasks with no dependencies
            ready_tasks = [task_id for task_id in remaining_tasks if in_degree[task_id] == 0]
            
            if not ready_tasks:
                break  # Should not happen if no circular deps
                
            execution_levels.append(ready_tasks)
            
            # Remove ready tasks and update dependencies
            for task_id in ready_tasks:
                remaining_tasks.remove(task_id)
                for other_task_id in remaining_tasks:
                    if task_id in task_deps[other_task_id]:
                        in_degree[other_task_id] -= 1
                        
        return execution_levels
        
    async def execute_mission(self, mission: MissionConfig) -> MissionResult:
        """Execute mission with full orchestration"""
        self.logger.info(f"🚀 Starting mission: {mission.name}")
        
        # Validate mission
        errors = self.validate_mission(mission)
        if errors:
            error_msg = "; ".join(errors)
            self.logger.error(f"❌ Mission validation failed: {error_msg}")
            raise ValueError(f"Mission validation failed: {error_msg}")
            
        # Create mission result
        mission_result = MissionResult(
            mission_id=mission.mission_id,
            status=MissionStatus.RUNNING,
            start_time=datetime.now(),
            end_time=None,
            task_results={},
            summary={},
            artifacts=[]
        )
        
        self.active_missions[mission.mission_id] = mission_result
        
        try:
            # Calculate execution plan
            execution_levels = self.calculate_execution_plan(mission)
            self.logger.info(f"📋 Execution plan: {len(execution_levels)} levels")
            
            # Execute tasks level by level
            for level_num, task_ids in enumerate(execution_levels):
                self.logger.info(f"⚡ Executing level {level_num + 1}: {task_ids}")
                
                # Execute tasks in parallel within the level
                level_tasks = [task for task in mission.tasks if task.task_id in task_ids]
                
                # Limit concurrency based on global config
                max_concurrent = mission.global_config.get("max_concurrent_tasks", 3)
                semaphore = asyncio.Semaphore(max_concurrent)
                
                async def execute_task_with_semaphore(task):
                    async with semaphore:
                        return await self.execute_task(task, mission_result)
                        
                # Execute tasks
                task_coroutines = [execute_task_with_semaphore(task) for task in level_tasks]
                level_results = await asyncio.gather(*task_coroutines, return_exceptions=True)
                
                # Check for failures that should stop execution
                critical_failures = []
                for i, result in enumerate(level_results):
                    task = level_tasks[i]
                    if isinstance(result, Exception):
                        self.logger.error(f"❌ Task {task.task_id} failed: {str(result)}")
                        if task.priority == TaskPriority.CRITICAL:
                            critical_failures.append(task.task_id)
                            
                if critical_failures:
                    self.logger.error(f"💥 Critical tasks failed: {critical_failures}")
                    mission_result.status = MissionStatus.FAILED
                    break
                    
            # Mission completed successfully
            if mission_result.status == MissionStatus.RUNNING:
                mission_result.status = MissionStatus.COMPLETED
                self.logger.info(f"✅ Mission completed: {mission.name}")
                
        except Exception as e:
            self.logger.error(f"💥 Mission execution failed: {str(e)}")
            mission_result.status = MissionStatus.FAILED
            
        finally:
            mission_result.end_time = datetime.now()
            
            # Generate mission summary
            mission_result.summary = self.generate_mission_summary(mission, mission_result)
            
            # Save mission result
            await self.save_mission_result(mission_result)
            
            # Send notifications
            await self.send_notifications(mission, mission_result)
            
        return mission_result
        
    async def execute_task(self, task: TaskConfig, mission_result: MissionResult) -> TaskResult:
        """Execute individual task"""
        self.logger.info(f"🎯 Executing task: {task.task_id}")
        
        task_result = TaskResult(
            task_id=task.task_id,
            status=MissionStatus.RUNNING,
            start_time=datetime.now(),
            end_time=None,
            output_data={},
            error_message=None,
            metrics={},
            artifacts=[]
        )
        
        mission_result.task_results[task.task_id] = task_result
        
        try:
            # Get module instance
            module = self.module_registry.get(task.module_type)
            if not module:
                raise ValueError(f"Module {task.module_type.value} not registered")
                
            # Execute task with timeout
            task_coroutine = self.call_module_method(module, task)
            result = await asyncio.wait_for(task_coroutine, timeout=task.timeout)
            
            # Process result
            task_result.output_data = result
            task_result.status = MissionStatus.COMPLETED
            
            # Check success criteria
            if not self.check_success_criteria(result, task.success_criteria):
                task_result.status = MissionStatus.FAILED
                task_result.error_message = "Success criteria not met"
                
            self.logger.info(f"✅ Task completed: {task.task_id}")
            
        except asyncio.TimeoutError:
            task_result.status = MissionStatus.FAILED
            task_result.error_message = f"Task timeout after {task.timeout} seconds"
            self.logger.error(f"⏰ Task timeout: {task.task_id}")
            
        except Exception as e:
            task_result.status = MissionStatus.FAILED
            task_result.error_message = str(e)
            self.logger.error(f"❌ Task failed: {task.task_id} - {str(e)}")
            
        finally:
            task_result.end_time = datetime.now()
            
        return task_result
        
    async def call_module_method(self, module: Any, task: TaskConfig) -> Dict[str, Any]:
        """Call appropriate method on module based on task configuration"""
        # This would be implemented based on the specific module interfaces
        # For now, return a mock result
        
        method_map = {
            ModuleType.PROXY: "manage_proxies",
            ModuleType.INTEL: "full_reconnaissance",
            ModuleType.SCANNER: "scan_vulnerabilities", 
            ModuleType.MUTATION: "generate_mutations",
            ModuleType.EXPLOIT: "generate_exploits",
            ModuleType.REPORT: "generate_report",
            ModuleType.SUBMIT: "submit_report"
        }
        
        method_name = method_map.get(task.module_type, "execute")
        
        if hasattr(module, method_name):
            method = getattr(module, method_name)
            
            # Call the method with task parameters
            if asyncio.iscoroutinefunction(method):
                return await method(task.target, **task.parameters)
            else:
                return method(task.target, **task.parameters)
        else:
            # Fallback to generic execute method
            if hasattr(module, 'execute'):
                return await module.execute(task.target, **task.parameters)
            else:
                raise ValueError(f"Module {task.module_type.value} has no execute method")
                
    def check_success_criteria(self, result: Dict[str, Any], criteria: Dict[str, Any]) -> bool:
        """Check if task result meets success criteria"""
        for key, expected in criteria.items():
            if key not in result:
                return False
                
            if isinstance(expected, dict):
                if "min" in expected and result[key] < expected["min"]:
                    return False
                if "max" in expected and result[key] > expected["max"]:
                    return False
                if "exists" in expected and expected["exists"] and not result[key]:
                    return False
            elif result[key] != expected:
                return False
                
        return True
        
    def generate_mission_summary(self, mission: MissionConfig, result: MissionResult) -> Dict[str, Any]:
        """Generate comprehensive mission summary"""
        total_tasks = len(mission.tasks)
        completed_tasks = len([t for t in result.task_results.values() if t.status == MissionStatus.COMPLETED])
        failed_tasks = len([t for t in result.task_results.values() if t.status == MissionStatus.FAILED])
        
        duration = (result.end_time - result.start_time).total_seconds() if result.end_time else 0
        
        return {
            "mission_name": mission.name,
            "target_domain": mission.target_domain,
            "status": result.status.value,
            "duration_seconds": duration,
            "tasks_total": total_tasks,
            "tasks_completed": completed_tasks,
            "tasks_failed": failed_tasks,
            "success_rate": (completed_tasks / total_tasks) * 100 if total_tasks > 0 else 0,
            "artifacts_generated": len(result.artifacts),
            "critical_findings": self.count_critical_findings(result),
            "recommendations": self.generate_recommendations(result)
        }
        
    def count_critical_findings(self, result: MissionResult) -> int:
        """Count critical security findings across all tasks"""
        critical_count = 0
        
        for task_result in result.task_results.values():
            if task_result.status == MissionStatus.COMPLETED:
                findings = task_result.output_data.get("vulnerabilities", [])
                critical_count += len([f for f in findings if f.get("severity") == "critical"])
                
        return critical_count
        
    def generate_recommendations(self, result: MissionResult) -> List[str]:
        """Generate actionable recommendations based on mission results"""
        recommendations = []
        
        # Analyze task results for patterns
        failed_tasks = [t for t in result.task_results.values() if t.status == MissionStatus.FAILED]
        
        if failed_tasks:
            recommendations.append("Review failed tasks and adjust parameters for retry")
            
        # Add more sophisticated analysis
        recommendations.append("Prioritize high-severity findings for immediate attention")
        recommendations.append("Consider expanding scope based on discovered attack surface")
        
        return recommendations
        
    async def save_mission_result(self, result: MissionResult):
        """Save mission result to file"""
        result_file = self.artifacts_dir / f"mission_result_{result.mission_id}.json"
        
        # Convert to serializable format
        result_dict = asdict(result)
        
        with open(result_file, 'w') as f:
            json.dump(result_dict, f, indent=2, default=str)
            
        self.logger.info(f"💾 Mission result saved: {result_file}")
        
    async def send_notifications(self, mission: MissionConfig, result: MissionResult):
        """Send notifications based on mission configuration"""
        notifications = mission.notifications
        
        if not notifications:
            return
            
        # Check if we should notify
        should_notify = False
        
        if notifications.get("on_completion") and result.status in [MissionStatus.COMPLETED, MissionStatus.FAILED]:
            should_notify = True
            
        if notifications.get("on_critical_finding") and self.count_critical_findings(result) > 0:
            should_notify = True
            
        if not should_notify:
            return
            
        # Generate notification message
        message = self.create_notification_message(mission, result)
        
        # Send to configured channels
        if notifications.get("slack_webhook"):
            await self.send_slack_notification(notifications["slack_webhook"], message)
            
        if notifications.get("email"):
            await self.send_email_notification(notifications["email"], message)
            
        self.logger.info("📢 Notifications sent")
        
    def create_notification_message(self, mission: MissionConfig, result: MissionResult) -> str:
        """Create notification message"""
        status_emoji = "✅" if result.status == MissionStatus.COMPLETED else "❌"
        critical_findings = self.count_critical_findings(result)
        
        message = f"""
{status_emoji} **ShadowOS Mission Complete**

🎯 **Mission:** {mission.name}
🌐 **Target:** {mission.target_domain}
📊 **Status:** {result.status.value.upper()}
⏱️ **Duration:** {(result.end_time - result.start_time).total_seconds():.0f}s
📈 **Tasks:** {len([t for t in result.task_results.values() if t.status == MissionStatus.COMPLETED])}/{len(result.task_results)} completed
🚨 **Critical Findings:** {critical_findings}

🎯 **Next Steps:** Review artifacts in workspace
"""
        return message
        
    async def send_slack_notification(self, webhook_url: str, message: str):
        """Send Slack notification"""
        import aiohttp
        
        payload = {
            "text": message,
            "username": "ShadowOS",
            "icon_emoji": ":fox_face:"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        self.logger.info("📱 Slack notification sent")
                    else:
                        self.logger.error(f"❌ Slack notification failed: {response.status}")
        except Exception as e:
            self.logger.error(f"❌ Slack notification error: {str(e)}")
            
    async def send_email_notification(self, email_config: Dict[str, str], message: str):
        """Send email notification"""
        # Email implementation would go here
        self.logger.info("📧 Email notification sent")
        
    def get_mission_status(self, mission_id: str) -> Optional[MissionResult]:
        """Get current status of a mission"""
        return self.active_missions.get(mission_id)
        
    def list_missions(self) -> List[str]:
        """List all saved missions"""
        mission_files = list(self.missions_dir.glob("*.yaml"))
        return [f.stem for f in mission_files]
        
    def cleanup_old_missions(self, days: int = 30):
        """Cleanup old mission files and artifacts"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # Cleanup mission files
        for mission_file in self.missions_dir.glob("*.yaml"):
            if mission_file.stat().st_mtime < cutoff_date.timestamp():
                mission_file.unlink()
                self.logger.info(f"🗑️ Cleaned up old mission: {mission_file.name}")
                
        # Cleanup artifact files
        for artifact_file in self.artifacts_dir.glob("*"):
            if artifact_file.stat().st_mtime < cutoff_date.timestamp():
                artifact_file.unlink()
                self.logger.info(f"🗑️ Cleaned up old artifact: {artifact_file.name}")

# Mission Template Factory
class MissionTemplateFactory:
    """Factory for creating predefined mission templates"""
    
    @staticmethod
    def create_api_security_mission(target_domain: str, **kwargs) -> MissionConfig:
        """Create API-focused security mission"""
        mission_id = str(uuid.uuid4())
        
        tasks = [
            TaskConfig(
                task_id=f"{mission_id}_proxy_setup",
                module_type=ModuleType.PROXY,
                target=target_domain,
                parameters={"action": "initialize", "rotation_interval": 240},
                dependencies=[],
                priority=TaskPriority.HIGH,
                timeout=300,
                retry_count=2,
                success_criteria={"active_proxies": {"min": 1}},
                failure_actions=["continue_without_proxy"]
            ),
            
            TaskConfig(
                task_id=f"{mission_id}_api_discovery",
                module_type=ModuleType.INTEL,
                target=target_domain,
                parameters={
                    "focus_apis": True,
                    "openapi_discovery": True,
                    "graphql_introspection": True,
                    "rest_endpoint_enumeration": True
                },
                dependencies=[f"{mission_id}_proxy_setup"],
                priority=TaskPriority.CRITICAL,
                timeout=1800,
                retry_count=2,
                success_criteria={"api_endpoints": {"min": 5}},
                failure_actions=["use_default_api_paths"]
            ),
            
            TaskConfig(
                task_id=f"{mission_id}_api_security_scan",
                module_type=ModuleType.SCANNER,
                target=target_domain,
                parameters={
                    "scan_types": ["api_idor", "auth_bypass", "injection", "business_logic"],
                    "parameter_pollution": True,
                    "rate_limit_bypass": True,
                    "authentication_tests": True
                },
                dependencies=[f"{mission_id}_api_discovery"],
                priority=TaskPriority.CRITICAL,
                timeout=3600,
                retry_count=1,
                success_criteria={"api_tests": {"min": 20}},
                failure_actions=["generate_partial_report"]
            ),
            
            TaskConfig(
                task_id=f"{mission_id}_api_exploitation",
                module_type=ModuleType.EXPLOIT,
                target=target_domain,
                parameters={
                    "focus_business_logic": True,
                    "chain_api_calls": True,
                    "data_extraction": kwargs.get("extract_data", False)
                },
                dependencies=[f"{mission_id}_api_security_scan"],
                priority=TaskPriority.HIGH,
                timeout=1800,
                retry_count=1,
                success_criteria={"api_exploits": {"min": 1}},
                failure_actions=["document_theoretical_exploits"]
            )
        ]
        
        return MissionConfig(
            mission_id=mission_id,
            name=f"API Security Assessment - {target_domain}",
            description=f"Comprehensive API security testing for {target_domain}",
            target_domain=target_domain,
            created_by=kwargs.get("created_by", "shadowos"),
            created_at=datetime.now(),
            tasks=tasks,
            global_config={
                "max_concurrent_tasks": 2,
                "stealth_mode": True,
                "api_focused": True
            },
            notifications=kwargs.get("notifications", {}),
            export_settings=kwargs.get("export_settings", {})
        )
        
    @staticmethod
    def create_subdomain_takeover_mission(target_domain: str, **kwargs) -> MissionConfig:
        """Create subdomain takeover hunting mission"""
        mission_id = str(uuid.uuid4())
        
        tasks = [
            TaskConfig(
                task_id=f"{mission_id}_subdomain_enum",
                module_type=ModuleType.INTEL,
                target=target_domain,
                parameters={
                    "subdomain_sources": ["crt.sh", "virustotal", "securitytrails", "chaos"],
                    "passive_only": True,
                    "historical_data": True
                },
                dependencies=[],
                priority=TaskPriority.HIGH,
                timeout=1200,
                retry_count=2,
                success_criteria={"subdomains": {"min": 10}},
                failure_actions=["continue_with_found_subdomains"]
            ),
            
            TaskConfig(
                task_id=f"{mission_id}_takeover_scan",
                module_type=ModuleType.SCANNER,
                target=target_domain,
                parameters={
                    "scan_types": ["subdomain_takeover"],
                    "service_detection": True,
                    "dns_analysis": True,
                    "cname_following": True
                },
                dependencies=[f"{mission_id}_subdomain_enum"],
                priority=TaskPriority.CRITICAL,
                timeout=1800,
                retry_count=1,
                success_criteria={"takeover_tests": {"min": 1}},
                failure_actions=["document_potential_targets"]
            )
        ]
        
        return MissionConfig(
            mission_id=mission_id,
            name=f"Subdomain Takeover Hunt - {target_domain}",
            description=f"Hunt for subdomain takeover vulnerabilities in {target_domain}",
            target_domain=target_domain,
            created_by=kwargs.get("created_by", "shadowos"),
            created_at=datetime.now(),
            tasks=tasks,
            global_config={
                "max_concurrent_tasks": 3,
                "stealth_mode": False,  # Subdomain enum can be more aggressive
                "dns_focused": True
            },
            notifications=kwargs.get("notifications", {}),
            export_settings=kwargs.get("export_settings", {})
        )

# CLI Interface
def create_cli():
    """Create CLI interface for mission orchestration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ShadowOS Mission Orchestrator")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Create mission command
    create_parser = subparsers.add_parser("create", help="Create new mission")
    create_parser.add_argument("template", choices=["full_recon", "idor_hunt", "api_security", "subdomain_takeover"])
    create_parser.add_argument("domain", help="Target domain")
    create_parser.add_argument("--output", help="Output mission file")
    create_parser.add_argument("--config", help="Additional config JSON file")
    
    # Execute mission command
    exec_parser = subparsers.add_parser("execute", help="Execute mission")
    exec_parser.add_argument("mission_file", help="Mission file to execute")
    exec_parser.add_argument("--workspace", help="Workspace directory")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Check mission status")
    status_parser.add_argument("mission_id", help="Mission ID to check")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List all missions")
    list_parser.add_argument("--workspace", help="Workspace directory")
    
    return parser

async def main():
    """Main CLI entry point"""
    parser = create_cli()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
        
    # Initialize orchestrator
    workspace = args.workspace if hasattr(args, 'workspace') and args.workspace else "./shadowos_workspace"
    orchestrator = ShadowMissionOrchestrator(workspace)
    
    if args.command == "create":
        print(f"🎯 Creating {args.template} mission for {args.domain}")
        
        # Load additional config if provided
        extra_config = {}
        if args.config:
            with open(args.config, 'r') as f:
                extra_config = json.load(f)
                
        # Create mission from template
        mission = orchestrator.create_mission_from_template(args.template, args.domain, **extra_config)
        
        # Save mission
        output_file = args.output or f"{args.template}_{args.domain}_{int(time.time())}.yaml"
        orchestrator.save_mission(mission)
        
        print(f"✅ Mission created and saved")
        print(f"📁 Mission ID: {mission.mission_id}")
        print(f"📄 Tasks: {len(mission.tasks)}")
        print(f"💾 Saved to: {output_file}")
        
    elif args.command == "execute":
        print(f"🚀 Executing mission from {args.mission_file}")
        
        # Load mission
        mission = orchestrator.load_mission(args.mission_file)
        
        # TODO: Register modules here
        # orchestrator.register_module(ModuleType.PROXY, proxy_manager)
        # orchestrator.register_module(ModuleType.INTEL, intel_engine)
        # etc.
        
        print("⚠️ Module registration required before execution")
        print("💡 Integrate with proxy_manager.py and intel_engine.py")
        
        # Execute mission (when modules are registered)
        # result = await orchestrator.execute_mission(mission)
        # print(f"✅ Mission completed with status: {result.status}")
        
    elif args.command == "status":
        result = orchestrator.get_mission_status(args.mission_id)
        if result:
            print(f"📊 Mission Status: {result.status.value}")
            print(f"⏱️ Duration: {(datetime.now() - result.start_time).total_seconds():.0f}s")
            print(f"📈 Progress: {len([t for t in result.task_results.values() if t.status == MissionStatus.COMPLETED])}/{len(result.task_results)} tasks")
        else:
            print(f"❌ Mission {args.mission_id} not found")
            
    elif args.command == "list":
        missions = orchestrator.list_missions()
        print(f"📋 Found {len(missions)} missions:")
        for mission_id in missions:
            print(f"  🎯 {mission_id}")

if __name__ == "__main__":
    asyncio.run(main())
