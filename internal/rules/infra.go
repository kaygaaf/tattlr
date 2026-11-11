package rules

import "strings"

// checkInfra flags commands that tear down cloud or cluster resources:
// terraform destroy, kubectl delete namespace, aws s3 rb --force and so on.
// These can't be undone with git, so they deserve a look even when the agent
// meant well.
func checkInfra(p string, args []string, add func(string, string, Severity)) {
	pos := positional(args[1:])
	sub := ""
	if len(pos) > 0 {
		sub = pos[0]
	}
	switch p {
	case "terraform", "tofu", "terragrunt":
		if sub == "destroy" || (sub == "apply" && hasLong(args, "-destroy", "--destroy")) {
			add(RuleInfraDestroy, p+" destroy", 0)
		} else if sub == "state" && len(pos) > 1 && pos[1] == "rm" {
			add(RuleInfraDestroy, p+" state rm", Medium)
		}
	case "pulumi", "cdk", "cdktf", "sst":
		if sub == "destroy" || sub == "remove" && p == "sst" {
			add(RuleInfraDestroy, p+" "+sub, 0)
		}
	case "kubectl", "oc":
		// Flags like "-n prod" come before the verb sometimes, so look for it.
		at := index(pos, "delete")
		if at < 0 {
			return
		}
		what := ""
		if at+1 < len(pos) {
			what = strings.ToLower(pos[at+1])
		}
		switch {
		case what == "namespace" || what == "namespaces" || what == "ns" || strings.HasPrefix(what, "namespace/") || strings.HasPrefix(what, "ns/"):
			add(RuleInfraDestroy, p+" delete namespace", 0)
		case hasLong(args, "--all", "--all-namespaces") || contains(args, "-A"):
			add(RuleInfraDestroy, p+" delete --all", 0)
		case what == "pv" || what == "pvc" || what == "persistentvolume" || what == "persistentvolumeclaim":
			add(RuleInfraDestroy, p+" delete "+what, 0)
		default:
			add(RuleInfraDestroy, p+" delete", Medium)
		}
	case "helm":
		if sub == "uninstall" || sub == "delete" || sub == "del" || sub == "un" {
			add(RuleInfraDestroy, "helm uninstall", Medium)
		}
	case "aws":
		// Skip values of global flags like "--profile prod" by starting at
		// the first word that is followed by an operation we know.
		svc, op := "", ""
		for i := 0; i+1 < len(pos); i++ {
			if pos[i] == "s3" || awsBigDeletes[pos[i]] || pos[i] == "ec2" {
				svc, op = pos[i], pos[i+1]
				break
			}
		}
		switch {
		case svc == "s3" && op == "rb" && hasLong(args, "--force"):
			add(RuleInfraDestroy, "aws s3 rb --force", 0)
		case svc == "s3" && op == "rm" && hasLong(args, "--recursive"):
			add(RuleInfraDestroy, "aws s3 rm --recursive", 0)
		case op == "terminate-instances" || strings.HasPrefix(op, "delete-") && awsBigDeletes[svc]:
			add(RuleInfraDestroy, "aws "+svc+" "+op, 0)
		}
	case "gcloud":
		for i, a := range pos {
			if a == "delete" && i > 0 {
				add(RuleInfraDestroy, "gcloud "+strings.Join(pos[:i+1], " "), 0)
				return
			}
		}
	case "az":
		if len(pos) > 1 && pos[0] == "group" && pos[1] == "delete" {
			add(RuleInfraDestroy, "az group delete", 0)
		}
	case "fly", "flyctl":
		if len(pos) > 1 && (pos[0] == "apps" || pos[0] == "volumes" || pos[0] == "postgres") && (pos[1] == "destroy" || pos[1] == "delete") {
			add(RuleInfraDestroy, p+" "+pos[0]+" "+pos[1], 0)
		}
	}
}

// awsBigDeletes are services where a delete-* call takes data or a whole
// stack with it.
var awsBigDeletes = map[string]bool{
	"rds":            true,
	"dynamodb":       true,
	"cloudformation": true,
	"eks":            true,
	"ecs":            true,
	"efs":            true,
	"elasticache":    true,
	"redshift":       true,
	"s3api":          true,
	"lambda":         true,
}

func index(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

// hasLong reports whether any of the given long flags is set, with or
// without a value.
func hasLong(args []string, flags ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		for _, f := range flags {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	return false
}
