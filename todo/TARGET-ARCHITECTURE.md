# Architecture I would steer toward

Conceptually:

```text
                        ┌───────────────────┐
                        │      WebUI        │
                        └─────────┬─────────┘
                                  │
                           API / Events
                                  │
                    ┌─────────────▼─────────────┐
                    │    Assessment Service      │
                    │                            │
                    │ Run / Scope / Credentials  │
                    └─────────────┬─────────────┘
                                  │
                         Immutable Mission
                                  │
                 ┌────────────────▼────────────────┐
                 │       Agent Orchestrator         │
                 │                                  │
                 │ Planner → Branch → Dispatcher    │
                 └──────────────┬───────────────────┘
                                │
                 ┌──────────────▼──────────────┐
                 │     Capability Firewall      │
                 │ scope / risk / permissions   │
                 └──────────────┬──────────────┘
                                │
                    ┌───────────▼──────────┐
                    │    Tool Registry      │
                    │ declarative manifests │
                    └───────────┬──────────┘
                                │
                  ┌─────────────▼─────────────┐
                  │ Disposable Sandbox Worker │
                  │ default-DROP network       │
                  └─────────────┬─────────────┘
                                │
                              Target
                                │
                 ┌──────────────▼──────────────┐
                 │ Observation / Evidence Bus   │
                 └──────────────┬──────────────┘
                                │
               ┌────────────────▼────────────────┐
               │ Independent Verification Engine │
               └────────────────┬────────────────┘
                                │
                        Verified Finding
                                │
              ┌─────────────────▼─────────────────┐
              │ Report / Ticket / Regression Test │
              └───────────────────────────────────┘
```

The critical design principle is:

> **The LLM chooses hypotheses and proposes actions. It does not define authority, facts, or verification truth.**

Your current design is already surprisingly close to that.

---

