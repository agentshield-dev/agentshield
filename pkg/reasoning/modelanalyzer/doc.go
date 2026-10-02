// Package modelanalyzer is the production [reasoning.Analyzer]: it connects a
// model client to the read-only MCP tools for one pinned analysis and retries
// failed attempts.
//
// Each attempt opens a fresh in-memory MCP session over the same
// [reasoning.ContextProvider] and runs [reasoning.AnalyzeCandidateWithTools].
// Only transport, MCP, and decoding errors are retried; a policy rejection is a
// successful analysis with a rejected outcome and is never retried into a
// different answer. Because every attempt sees the same pinned packet and
// graph digest, a retry cannot observe newer state. When all attempts fail,
// the error stops the reasoning service; see [reasoning.Service.Run].
package modelanalyzer
