// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cryft-labs/cryftgo/snow/engine/snowman/block (interfaces: BuildBlockWithContextChainVM)
//
// Generated by this command:
//
//	mockgen -package=block -destination=snow/engine/snowman/block/mock_build_block_with_context_vm.go github.com/cryft-labs/cryftgo/snow/engine/snowman/block BuildBlockWithContextChainVM
//

// Package block is a generated GoMock package.
package block

import (
	context "context"
	reflect "reflect"

	snowman "github.com/cryft-labs/cryftgo/snow/consensus/snowman"
	gomock "go.uber.org/mock/gomock"
)

// MockBuildBlockWithContextChainVM is a mock of BuildBlockWithContextChainVM interface.
type MockBuildBlockWithContextChainVM struct {
	ctrl     *gomock.Controller
	recorder *MockBuildBlockWithContextChainVMMockRecorder
}

// MockBuildBlockWithContextChainVMMockRecorder is the mock recorder for MockBuildBlockWithContextChainVM.
type MockBuildBlockWithContextChainVMMockRecorder struct {
	mock *MockBuildBlockWithContextChainVM
}

// NewMockBuildBlockWithContextChainVM creates a new mock instance.
func NewMockBuildBlockWithContextChainVM(ctrl *gomock.Controller) *MockBuildBlockWithContextChainVM {
	mock := &MockBuildBlockWithContextChainVM{ctrl: ctrl}
	mock.recorder = &MockBuildBlockWithContextChainVMMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBuildBlockWithContextChainVM) EXPECT() *MockBuildBlockWithContextChainVMMockRecorder {
	return m.recorder
}

// BuildBlockWithContext mocks base method.
func (m *MockBuildBlockWithContextChainVM) BuildBlockWithContext(arg0 context.Context, arg1 *Context) (snowman.Block, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuildBlockWithContext", arg0, arg1)
	ret0, _ := ret[0].(snowman.Block)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BuildBlockWithContext indicates an expected call of BuildBlockWithContext.
func (mr *MockBuildBlockWithContextChainVMMockRecorder) BuildBlockWithContext(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuildBlockWithContext", reflect.TypeOf((*MockBuildBlockWithContextChainVM)(nil).BuildBlockWithContext), arg0, arg1)
}