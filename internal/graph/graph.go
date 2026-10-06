// Package graph builds the evidence graph connecting APK → DEX → method → findings.
package graph

import (
	"fmt"
	"strings"

	"github.com/armin/apkcheck/pkg/model"
)

// Build constructs a navigable evidence graph from an analysis result.
func Build(r *model.AnalysisResult) *model.EvidenceGraph {
	if r == nil {
		return nil
	}
	g := &model.EvidenceGraph{}
	apkID := "apk:0"
	addNode(g, apkID, "apk", r.APK.Path, map[string]string{
		"sha256":  r.APK.SHA256,
		"package": r.APK.Package,
	}, "")

	manID := "manifest:0"
	addNode(g, manID, "manifest", "AndroidManifest.xml", nil, apkID)
	addEdge(g, apkID, manID, "contains", model.EvidenceStatic)

	if r.Bundle != nil {
		for i, s := range r.Bundle.Splits {
			sid := fmt.Sprintf("split:%d", i)
			addNode(g, sid, "split", s.Name, map[string]string{"kind": s.Kind, "path": s.Path}, apkID)
			addEdge(g, apkID, sid, "contains", model.EvidenceStatic)
		}
	}

	for i, dex := range r.APK.DEXFiles {
		did := fmt.Sprintf("dex:%d", i)
		attrs := map[string]string{}
		if r.APK.SplitOrigins != nil {
			attrs["split"] = r.APK.SplitOrigins[dex]
		}
		addNode(g, did, "dex", dex, attrs, apkID)
		addEdge(g, apkID, did, "contains", model.EvidenceStatic)
	}

	classNodes := map[string]string{}
	for i, m := range r.Methods {
		cid, ok := classNodes[m.Ref.Class]
		if !ok {
			cid = fmt.Sprintf("class:%s", m.Ref.Class)
			classNodes[m.Ref.Class] = cid
			addNode(g, cid, "class", m.Ref.Class, nil, apkID)
			addEdge(g, apkID, cid, "contains", model.EvidenceStatic)
		}
		mid := fmt.Sprintf("method:%d", i)
		addNode(g, mid, "method", m.Ref.String(), map[string]string{
			"status":   string(m.Status),
			"semantic": string(m.SemanticConfidence),
		}, cid)
		addEdge(g, cid, mid, "declares", model.EvidenceStatic)

		smaliID := mid + ":smali"
		addNode(g, smaliID, "smali", "Smali ground truth", nil, mid)
		addEdge(g, mid, smaliID, "contains", model.EvidenceStatic)

		for name, d := range m.Decompilers {
			did := fmt.Sprintf("%s:decompiled:%s", mid, name)
			addNode(g, did, "decompiled", name, map[string]string{
				"status": string(d.Status),
				"path":   d.SourcePath,
			}, mid)
			addEdge(g, mid, did, "decompiles_to", model.EvidenceStatic)
		}
	}

	for i, n := range r.Native {
		nid := fmt.Sprintf("native:%d", i)
		addNode(g, nid, "native", n.Path, map[string]string{"abi": n.ABI, "split": n.Split}, apkID)
		addEdge(g, apkID, nid, "contains", model.EvidenceStatic)
	}
	for i, j := range r.JNI {
		jid := fmt.Sprintf("jni:%d", i)
		label := j.ClassName + "." + j.Method
		addNode(g, jid, "jni", label, map[string]string{
			"library": j.Library,
			"symbol":  j.JNISymbol,
		}, apkID)
		addEdge(g, apkID, jid, "maps_to", j.EClass)
		if j.Library != "" {
			for ni, n := range r.Native {
				if n.Name == j.Library || strings.HasSuffix(n.Path, j.Library) {
					addEdge(g, jid, fmt.Sprintf("native:%d", ni), "maps_to", j.EClass)
					break
				}
			}
		}
	}

	for i, f := range r.Findings {
		fid := fmt.Sprintf("finding:%d", i)
		addNode(g, fid, "finding", f.Title, map[string]string{
			"severity": string(f.Severity),
			"class":    string(f.Class),
			"id":       f.ID,
		}, apkID)
		addEdge(g, apkID, fid, "supports", f.Class)
		for _, e := range f.Evidence {
			if e.Class != "" {
				if cid, ok := classNodes[e.Class]; ok {
					addEdge(g, fid, cid, "supports", f.Class)
				}
			}
			if e.Method != "" && e.Class != "" {
				// best-effort link to method node
				for mi, m := range r.Methods {
					if m.Ref.Class == e.Class && m.Ref.Name == e.Method {
						addEdge(g, fid, fmt.Sprintf("method:%d", mi), "supports", f.Class)
						break
					}
				}
			}
		}
	}

	for i, o := range r.RuntimeObs {
		oid := fmt.Sprintf("runtime:%d", i)
		addNode(g, oid, "runtime", o.Kind+": "+o.Message, map[string]string{"status": o.Status}, apkID)
		addEdge(g, apkID, oid, "observes", model.EvidenceRuntime)
	}

	return g
}

func addNode(g *model.EvidenceGraph, id, kind, label string, attrs map[string]string, parent string) {
	g.Nodes = append(g.Nodes, model.GraphNode{
		ID: id, Kind: kind, Label: label, Attrs: attrs, ParentID: parent,
	})
}

func addEdge(g *model.EvidenceGraph, from, to, rel string, cls model.EvidenceClass) {
	g.Edges = append(g.Edges, model.GraphEdge{
		From: from, To: to, Rel: rel, Class: cls,
	})
}
