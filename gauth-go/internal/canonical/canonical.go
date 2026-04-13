// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Gimel Foundation gGmbH i.G.

package canonical

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

func JSON(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical json marshal: %w", err)
	}

	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("canonical json unmarshal: %w", err)
	}

	sorted := sortValue(generic)
	return json.Marshal(sorted)
}

func SHA256Hex(v interface{}) (string, error) {
	data, err := JSON(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h), nil
}

func sortValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sorted := make(sortedMap, 0, len(val))
		for _, k := range keys {
			sorted = append(sorted, sortedEntry{Key: k, Value: sortValue(val[k])})
		}
		return sorted
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = sortValue(item)
		}
		return result
	default:
		return v
	}
}

type sortedEntry struct {
	Key   string
	Value interface{}
}

type sortedMap []sortedEntry

func (s sortedMap) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, entry := range s {
		if i > 0 {
			buf = append(buf, ',')
		}
		key, err := json.Marshal(entry.Key)
		if err != nil {
			return nil, err
		}
		val, err := json.Marshal(entry.Value)
		if err != nil {
			return nil, err
		}
		buf = append(buf, key...)
		buf = append(buf, ':')
		buf = append(buf, val...)
	}
	buf = append(buf, '}')
	return buf, nil
}
