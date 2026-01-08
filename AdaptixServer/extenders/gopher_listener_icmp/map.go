package main

import (
	"sync"
)

// Map 提供线程安全的键值存储
// Thread-safe key-value storage for managing connections
type Map struct {
	mutex sync.RWMutex
	m     map[string]interface{}
}

// NewMap 创建新的线程安全Map
// Creates a new thread-safe Map
func NewMap() Map {
	return Map{
		m: make(map[string]interface{}),
	}
}

// Contains 检查键是否存在
// Checks if a key exists in the map
func (s *Map) Contains(key string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	_, exists := s.m[key]
	return exists
}

// Put 添加或更新键值对
// Adds or updates a key-value pair
func (s *Map) Put(key string, value interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.m[key] = value
}

// Get 获取键对应的值
// Gets the value for a key
func (s *Map) Get(key string) (interface{}, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	value, exists := s.m[key]
	return value, exists
}

// Delete 删除键值对
// Deletes a key-value pair
func (s *Map) Delete(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.m, key)
}

// GetDelete 获取并删除键值对
// Gets and deletes a key-value pair atomically
func (s *Map) GetDelete(key string) (interface{}, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if value, exists := s.m[key]; exists {
		delete(s.m, key)
		return value, true
	}
	return nil, false
}

// Len 返回Map中元素数量
// Returns the number of elements in the map
func (s *Map) Len() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.m)
}

// ForEach 遍历所有键值对
// Iterates over all key-value pairs
func (s *Map) ForEach(f func(key string, value interface{}) bool) {
	s.mutex.RLock()
	copyMap := make(map[string]interface{}, len(s.m))
	for k, v := range s.m {
		copyMap[k] = v
	}
	s.mutex.RUnlock()

	for key, value := range copyMap {
		if !f(key, value) {
			break
		}
	}
}

// DirectLock 获取读锁（用于直接访问）
// Acquires read lock for direct access
func (s *Map) DirectLock() {
	s.mutex.RLock()
}

// DirectUnlock 释放读锁
// Releases read lock
func (s *Map) DirectUnlock() {
	s.mutex.RUnlock()
}

// DirectMap 返回内部map的引用（需要先调用DirectLock）
// Returns reference to internal map (must call DirectLock first)
func (s *Map) DirectMap() map[string]interface{} {
	return s.m
}

// CutMap 获取并清空Map
// Gets and clears the map atomically
func (s *Map) CutMap() map[string]interface{} {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldMap := s.m
	s.m = make(map[string]interface{})

	return oldMap
}
