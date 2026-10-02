package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestControlplaneStartsStripeCheckoutAssociationMonitor(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "run" {
			continue
		}
		for _, statement := range function.Body.List {
			expression, ok := statement.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := expression.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "StartStripeCheckoutAssociationMonitor" || len(call.Args) != 1 {
				continue
			}
			receiver, receiverOK := selector.X.(*ast.Ident)
			arg, argOK := call.Args[0].(*ast.Ident)
			if receiverOK && argOK && receiver.Name == "handlers" && arg.Name == "ctx" {
				return
			}
		}
		t.Fatal("run does not start the Stripe checkout association monitor with the root context")
	}
	t.Fatal("control-plane run function not found")
}
