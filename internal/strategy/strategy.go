package strategy

import "github.com/fitting-1c/evasion/internal/core"

// Strategy — стратегия обхода: набор правил. Это то, что мутирует генератор.
// О пакетах, сокетах и сети не знает.
//
// ID выводится из канонической формы Rules (см. canonical.go) и не является
// независимым полем: его нельзя задать произвольно, он всегда согласован с
// содержимым.
type Strategy struct {
	ID    core.StrategyID
	Rules []Rule
}

// Rule — при каком пакете правило срабатывает и что с ним делать.
type Rule struct {
	// Direction — к какой стороне трафика относится правило.
	Direction core.Direction `json:"direction"`
	// Trigger — условие срабатывания.
	Trigger Trigger `json:"trigger"`
	// Action — корень дерева действий, применяемого при срабатывании.
	Action *Action `json:"action"`
}

// Action — узел двоичного дерева действий.
//
// Листья (Send, Drop) терминальны; внутренние узлы (Tamper, Fragment,
// Duplicate) преобразуют пакет и передают результат в ветви. Арность задаётся
// видом (core.ActionKind.Arity) и проверяется валидацией:
//
//	Tamper              — только Left;
//	Duplicate, Fragment — Left и Right;
//	Send, Drop          — ветвей нет.
type Action struct {
	// Kind — вид узла.
	Kind core.ActionKind
	// Params — параметры преобразования. nil у листьев и у Duplicate.
	Params Params
	// Left — первая (или единственная) ветвь.
	Left *Action
	// Right — вторая ветвь (у Duplicate и Fragment).
	Right *Action
}
