//! The output sink (PERF-05).
//!
//! Before this, `scan_binary` materialized every candidate gadget from every
//! (region × anchor) work item into one `Vec` before dedup — measured at
//! ~117 bytes of RSS per byte of scanned code. The scan now *drives* a sink,
//! so a caller that cannot afford the full listing (the MCP server, a
//! 100 MB input) can bound it: [`BoundedSink`] stops the scan the moment the
//! gadget count or the retained-byte estimate crosses the caller's limit,
//! and the scan's remaining work items collapse to one atomic load each.
//!
//! [`VecSink`] is the unbounded implementation the classic entry points use.

use crate::cancel::Error;
use crate::engine::Gadget;

/// Receives accepted gadgets in traversal order (section → table → anchor →
/// anchor-hit → depth), the order dedup's first-occurrence-wins rule depends
/// on.
pub trait GadgetSink {
    /// Accept one gadget. Returning `Err` aborts the scan.
    fn accept(&mut self, g: Gadget) -> Result<(), Error>;

    /// How many gadgets have been accepted so far.
    fn accepted(&self) -> usize;

    /// Remaining gadget headroom, if the sink is bounded. The scan loops
    /// consult this to stop producing rather than to produce-then-reject.
    fn remaining(&self) -> Option<usize> {
        None
    }
}

/// Estimated heap footprint of one gadget: the struct itself plus the byte
/// vector, the per-instruction strings and the optional `prev` capture.
pub fn gadget_bytes(g: &Gadget) -> usize {
    std::mem::size_of::<Gadget>()
        + g.bytes.capacity()
        + g.insns
            .iter()
            .map(|s| s.capacity() + std::mem::size_of::<String>())
            .sum::<usize>()
        + g.prev.as_ref().map_or(0, |p| p.capacity())
}

/// Unbounded collector: the classic behaviour.
#[derive(Debug, Default)]
pub struct VecSink {
    pub gadgets: Vec<Gadget>,
}

impl VecSink {
    pub fn new() -> Self {
        VecSink::default()
    }
    pub fn into_inner(self) -> Vec<Gadget> {
        self.gadgets
    }
}

impl GadgetSink for VecSink {
    fn accept(&mut self, g: Gadget) -> Result<(), Error> {
        self.gadgets.push(g);
        Ok(())
    }
    fn accepted(&self) -> usize {
        self.gadgets.len()
    }
}

/// Bounded collector: stops the scan with [`Error::Budget`] once
/// `max_gadgets` or `max_memory` (estimated retained bytes) is crossed.
#[derive(Debug, Default)]
pub struct BoundedSink {
    gadgets: Vec<Gadget>,
    bytes: usize,
    max_gadgets: Option<usize>,
    max_memory: Option<usize>,
}

impl BoundedSink {
    pub fn new(max_gadgets: Option<usize>, max_memory: Option<usize>) -> Self {
        BoundedSink {
            gadgets: Vec::new(),
            bytes: 0,
            max_gadgets,
            max_memory,
        }
    }
    /// Estimated retained heap bytes.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn into_inner(self) -> Vec<Gadget> {
        self.gadgets
    }
}

impl GadgetSink for BoundedSink {
    fn accept(&mut self, g: Gadget) -> Result<(), Error> {
        if let Some(limit) = self.max_gadgets {
            if self.gadgets.len() >= limit {
                return Err(Error::Budget {
                    produced: self.gadgets.len(),
                    limit,
                });
            }
        }
        let add = gadget_bytes(&g);
        if let Some(limit) = self.max_memory {
            if self.bytes + add > limit {
                return Err(Error::Budget {
                    produced: self.gadgets.len(),
                    limit,
                });
            }
        }
        self.bytes += add;
        self.gadgets.push(g);
        Ok(())
    }
    fn accepted(&self) -> usize {
        self.gadgets.len()
    }
    fn remaining(&self) -> Option<usize> {
        self.max_gadgets
            .map(|m| m.saturating_sub(self.gadgets.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(n: usize) -> Gadget {
        Gadget {
            vaddr: n as u64,
            bytes: vec![0xc3],
            insns: vec!["ret".to_string()],
            delay_slot: false,
            prev: None,
            table: crate::anchors::TableKind::Rop,
        }
    }

    #[test]
    fn vec_sink_is_unbounded() {
        let mut s = VecSink::new();
        for i in 0..1000 {
            s.accept(g(i)).unwrap();
        }
        assert_eq!(s.accepted(), 1000);
        assert_eq!(s.remaining(), None);
    }

    #[test]
    fn bounded_sink_stops_at_max_gadgets() {
        let mut s = BoundedSink::new(Some(3), None);
        for i in 0..3 {
            s.accept(g(i)).unwrap();
        }
        assert_eq!(s.remaining(), Some(0));
        assert_eq!(
            s.accept(g(4)),
            Err(Error::Budget {
                produced: 3,
                limit: 3
            })
        );
        assert_eq!(s.into_inner().len(), 3);
    }

    #[test]
    fn bounded_sink_stops_at_max_memory() {
        let one = gadget_bytes(&g(0));
        let mut s = BoundedSink::new(None, Some(one * 2));
        s.accept(g(0)).unwrap();
        s.accept(g(1)).unwrap();
        assert!(matches!(s.accept(g(2)), Err(Error::Budget { .. })));
        assert_eq!(s.accepted(), 2);
        assert!(s.bytes() <= one * 2);
    }
}
