//! Jump table representation.
//!
//! Jump tables are declared in the preamble and assigned an `ir::entities::JumpTable` reference.
//! The actual table of destinations is stored in a `JumpTableData` struct defined in this module.

use crate::ir::entities::Block;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};
use core::slice::{Iter, IterMut};

// for now we are limited to storing 32-bit labels in the jump table
// this is because the x86 encoding of jump_table_entry requires that
// the table entry size is a valid SIB byte (as determined by the
// `valid_scale()` function), of which 8 is the largest valid value
type CFILabel = u32;
const LABEL_VALUE: CFILabel = 10;

/// Contents of a jump table.
///
/// All jump tables use 0-based indexing and are densely populated.
#[derive(Clone)]
pub struct JumpTableData {
    // Table entries.
    table: Vec<(Block, CFILabel)>,
}

impl JumpTableData {
    /// Create a new empty jump table.
    pub fn new() -> Self {
        Self { table: Vec::new() }
    }

    /// Create a new empty jump table with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            table: Vec::with_capacity(capacity),
        }
    }

    /// Get the number of table entries.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Append a table entry.
    pub fn push_entry(&mut self, dest: Block) {
        // for now we use the constant LABEL_VALUE
        self.table.push((dest, LABEL_VALUE))
    }

    /// Checks if any of the entries branch to `block`.
    pub fn branches_to(&self, block: Block) -> bool {
        self.table.iter().any(|(target_block, _)| *target_block == block)
    }

    /// Access the whole table as a slice.
    pub fn as_slice(&self) -> &[(Block, CFILabel)] {
        self.table.as_slice()
    }

    /// Access the whole table as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [(Block, CFILabel)] {
        self.table.as_mut_slice()
    }

    /// Returns an iterator over the (block, label) pairs in the table.
    pub fn iter(&self) -> Iter<(Block, CFILabel)> {
        self.table.iter()
    }

    /// Returns an iterator that allows modifying each (block, label) pair.
    pub fn iter_mut(&mut self) -> IterMut<(Block, CFILabel)> {
        self.table.iter_mut()
    }

    /// Returns an iterator over the blocks in the table.
    pub fn iter_blocks<'a>(&'a self) -> impl Iterator<Item = Block> + 'a {
        self.iter().map(|&(block, _)| block)
    }

    /// Returns an iterator that allows modifying each block in the table.
    pub fn iter_mut_blocks<'a>(&'a mut self) -> impl Iterator<Item = &'a mut Block> + 'a {
        self.iter_mut().map(|(block, _)| block)
    }
}

impl Display for JumpTableData {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(fmt, "jump_table [")?;
        match self.table.first() {
            None => (),
            Some((first_block, first_label)) => write!(fmt, "{} [{}]", first_block, first_label)?,
        }
        for (block, label) in self.table.iter().skip(1) {
            write!(fmt, ", {} [{}]", block, label)?;
        }
        write!(fmt, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::JumpTableData;
    use crate::entity::EntityRef;
    use crate::ir::Block;
    use alloc::string::ToString;

    #[test]
    fn empty() {
        let jt = JumpTableData::new();

        assert_eq!(jt.as_slice().get(0), None);
        assert_eq!(jt.as_slice().get(10), None);

        assert_eq!(jt.to_string(), "jump_table []");

        let v = jt.as_slice();
        assert_eq!(v, []);
    }

    #[test]
    fn insert() {
        let e1 = Block::new(1);
        let e2 = Block::new(2);

        let mut jt = JumpTableData::new();

        jt.push_entry(e1);
        jt.push_entry(e2);
        jt.push_entry(e1);

        assert_eq!(jt.to_string(), "jump_table [block1, block2, block1]");

        let v = jt.as_slice();
        assert_eq!(v, [e1, e2, e1]);
    }
}
