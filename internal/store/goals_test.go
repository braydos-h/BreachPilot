package store_test

import (
	"testing"

	"github.com/braydos-h/BreachPilot/internal/store"
)

func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(t.TempDir()+"/t.db", t.TempDir()+"/reports")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestCustomGoalCRUD(t *testing.T) {
	db := openTestDB(t)
	g, err := db.CreateCustomGoal("g1", "My Goal", "do things")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "My Goal" || g.CreatedAt == "" {
		t.Fatalf("goal: %+v", g)
	}
	if _, err := db.CreateCustomGoal("g2", "my goal", "dup"); err == nil {
		t.Fatal("case-insensitive duplicate must fail")
	}
	list, err := db.ListCustomGoals()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	got, err := db.GetCustomGoal("g1")
	if err != nil || got == nil || got.Objective != "do things" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if missing, _ := db.GetCustomGoal("nope"); missing != nil {
		t.Fatal("missing id must return nil")
	}
	upd, err := db.UpdateCustomGoal("g1", "", "do other things")
	if err != nil || upd.Objective != "do other things" || upd.Name != "My Goal" {
		t.Fatalf("update: %+v %v", upd, err)
	}
	ok, err := db.DeleteCustomGoal("g1")
	if err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	ok, _ = db.DeleteCustomGoal("g1")
	if ok {
		t.Fatal("second delete must report false")
	}
}

func TestDecisionLifecycle(t *testing.T) {
	db := openTestDB(t)
	dec, err := db.CreateDecision("d1", "r1", "start_confirm", "Confirm?", "ALLOW x")
	if err != nil || dec.Status != "pending" {
		t.Fatalf("create: %+v %v", dec, err)
	}
	list, err := db.ListDecisions("r1")
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	if err := db.AnswerDecision("d1", "ALLOW x"); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetDecision("r1", "d1")
	if got.Status != "answered" || got.Answer != "ALLOW x" {
		t.Fatalf("answered: %+v", got)
	}
	if wrong, _ := db.GetDecision("other", "d1"); wrong != nil {
		t.Fatal("cross-run decision access must return nil")
	}
	if _, err := db.CreateDecision("d2", "r1", "goal_select", "Pick", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.CancelDecisions("r1"); err != nil {
		t.Fatal(err)
	}
	got2, _ := db.GetDecision("r1", "d2")
	if got2.Status != "cancelled" {
		t.Fatalf("cancelled: %+v", got2)
	}
}
