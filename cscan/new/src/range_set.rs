type Range = std::ops::Range<u64>;
use std::cmp::Ordering;

/// Ordered storage for `u64`s.
#[derive(Debug)]
pub struct RangeSet {
    ranges: Vec<Range>,
}

pub struct ElementIter<'a> {
    ranges: &'a [Range],
    i: usize,
    j: u64,
}

impl Iterator for ElementIter<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        // If current range is not available, then the iter is already depleted.
        let range = self.ranges.get(self.i)?;
        // Return if inside current range.
        let r = range.start + self.j;
        if range.contains(&r) {
            self.j += 1;
            return Some(r);
        }
        // Outside of current range: try next.
        self.i += 1;
        let range = self.ranges.get(self.i)?;
        // According to the specification, current range must be non-empty.
        // We can safely take range[0], and the advance to range[1].
        self.j = 1;
        Some(range.start)
    }
}

impl Default for RangeSet {
    fn default() -> Self {
        Self { ranges: vec![] }
    }
}

impl RangeSet {
    pub fn len(&self) -> u64 {
        self.ranges
            .iter()
            .map(|range| range.end - range.start)
            .sum()
    }

    pub fn elements(&self) -> ElementIter {
        ElementIter {
            ranges: &self.ranges,
            i: 0,
            j: 0,
        }
    }

    pub fn ranges(&self) -> &[Range] {
        &self.ranges
    }

    pub fn into_ranges(self) -> Vec<Range> {
        self.ranges
    }

    pub fn push(&mut self, v: u64) {
        if let Some(last) = self.ranges.last().cloned() {
            match v.cmp(&last.end) {
                Ordering::Less => panic!("unordered value"),
                Ordering::Equal => self.ranges.last_mut().unwrap().end = v + 1,
                Ordering::Greater => self.ranges.push(v..v + 1),
            }
        } else {
            self.ranges.push(v..v + 1)
        }
    }

    /// The ranges should be sorted, non-empty and non-overlapping.
    pub fn from_raw_ranges<I: IntoIterator<Item = Range>>(ranges: I) -> Self {
        let ranges: Vec<_> = ranges.into_iter().collect();
        for i in 1..ranges.len() {
            let (prev, next) = (&ranges[i - 1], &ranges[i]);
            assert!(prev.end > prev.start, "empty range {:?}", prev);
            assert!(prev.end <= next.start, "unordered or overlapping ranges")
        }
        if let Some(last) = ranges.last() {
            assert!(last.end > last.start, "empty range (last) {:?}", last);
        }
        Self { ranges }
    }

    pub fn contains(&self, v: u64) -> bool {
        match self.ranges.binary_search_by(|r| r.start.cmp(&v)) {
            // ranges[i].start == v,
            Ok(_) => true,
            // v should be inserted at ranges[i], which means ranges[i].start > v
            // ranges[i - 1] may contain v.
            Err(i) => {
                if i == 0 {
                    // Too small
                    false
                } else {
                    self.ranges[i - 1].contains(&v)
                }
            }
        }
    }
}

#[cfg(test)]
#[test]
fn test_elements() {
    let ranges = &[
        0..1,
        1..2,
        2..3,
        4..5,
        6..8,
        100..1000,
        1000..1001,
        1005..1006,
        10010..10100,
    ];

    let mut raw = ranges.iter().cloned().flatten();
    let t = RangeSet::from_raw_ranges(ranges.iter().cloned());
    let mut mine = t.elements();
    loop {
        match (raw.next(), mine.next()) {
            (None, None) => break,
            (x, y) => assert_eq!(x, y),
        }
    }
}
