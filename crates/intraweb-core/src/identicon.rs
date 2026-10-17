//! A picture of a key.
//!
//! Fingerprints are the honest way to tell two people apart, and nobody reads
//! them. They skim the first group and stop, which is exactly the gap a ground
//! lookalike key walks through.
//!
//! People are far better at noticing that a picture changed than that
//! `09fc-d332` became `09fc-d441`, so every key also gets a shape derived from
//! the whole of it. The grid is mirrored because symmetry is what makes a
//! pattern memorable rather than noise.
//!
//! This is a readability aid, not a security boundary: the drawing has less
//! entropy than the fingerprint it illustrates. Confirming somebody still
//! means comparing the fingerprint itself.

use crate::identity::PeerId;
use sha2::{Digest, Sha256};

/// Cells across. Odd, so there is a centre column to mirror around.
const GRID: usize = 7;
/// Columns actually drawn from the hash; the rest are mirrored.
const UNIQUE_COLUMNS: usize = GRID.div_ceil(2);

/// Deterministic SVG for a key, at the given pixel size.
///
/// Same key, same picture, on every node and forever -- there is nothing
/// random and nothing stored.
pub fn svg(peer_id: PeerId, size: u32) -> String {
    let digest: [u8; 32] = Sha256::digest(peer_id.as_bytes()).into();

    // Last bytes pick the colour so it is independent of the cells.
    let (foreground, background) = palette(digest[31], digest[30]);

    let cell = size as f32 / GRID as f32;
    let mut rects = String::new();

    for column in 0..UNIQUE_COLUMNS {
        for row in 0..GRID {
            // One bit per cell, taken from the first half of the digest.
            let bit_index = column * GRID + row;
            let byte = digest[bit_index / 8];
            if byte >> (bit_index % 8) & 1 == 0 {
                continue;
            }
            for x in [column, GRID - 1 - column] {
                rects.push_str(&format!(
                    r#"<rect x="{:.2}" y="{:.2}" width="{:.2}" height="{:.2}"/>"#,
                    x as f32 * cell,
                    row as f32 * cell,
                    cell.ceil(),
                    cell.ceil(),
                ));
            }
        }
    }

    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" aria-label="key pattern"><rect width="{size}" height="{size}" fill="{background}"/><g fill="{foreground}">{rects}</g></svg>"#
    )
}

/// A readable pair of colours: one saturated hue against a pale wash of it.
///
/// Hues are spread across the wheel so two keys rarely look alike at a glance,
/// and lightness is fixed so every icon stays legible in both themes.
fn palette(hue_byte: u8, shift_byte: u8) -> (String, String) {
    let hue = (hue_byte as u32 * 360) / 256;
    // A second hue a little away from the first keeps the wash from looking
    // like a faded version of the same colour.
    let wash_hue = (hue + 20 + (shift_byte as u32 % 40)) % 360;
    (
        format!("hsl({hue} 58% 42%)"),
        format!("hsl({wash_hue} 36% 92%)"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn key() -> PeerId {
        Identity::generate().unwrap().peer_id()
    }

    #[test]
    fn the_same_key_always_draws_the_same_picture() {
        // Every node must draw a given person identically, forever.
        let peer = key();
        assert_eq!(svg(peer, 64), svg(peer, 64));
    }

    #[test]
    fn different_keys_draw_different_pictures() {
        assert_ne!(svg(key(), 64), svg(key(), 64));
    }

    #[test]
    fn the_picture_is_well_formed_svg() {
        let drawing = svg(key(), 64);
        assert!(drawing.starts_with("<svg"));
        assert!(drawing.ends_with("</svg>"));
        assert_eq!(
            drawing.matches("<rect").count(),
            drawing.matches("/>").count()
        );
        assert!(drawing.contains(r#"viewBox="0 0 64 64""#));
    }

    #[test]
    fn the_picture_is_symmetric() {
        // Symmetry is what makes the shape memorable rather than noise.
        let drawing = svg(key(), 70);
        let xs: Vec<String> = drawing
            .match_indices(r#"<rect x=""#)
            .map(|(i, _)| drawing[i + 9..].split('"').next().unwrap_or("").to_string())
            .collect();

        // Every drawn column has a mirror partner at the same count.
        for x in &xs {
            let value: f32 = x.parse().unwrap_or(-1.0);
            let mirrored = 70.0 - 10.0 - value;
            assert!(
                xs.iter()
                    .any(|other| (other.parse::<f32>().unwrap_or(-1.0) - mirrored).abs() < 0.1),
                "column at {x} has no mirror",
            );
        }
    }

    #[test]
    fn it_scales_without_changing_the_pattern() {
        let peer = key();
        let small = svg(peer, 32);
        let large = svg(peer, 128);
        assert_eq!(
            small.matches("<rect").count(),
            large.matches("<rect").count()
        );
    }

    #[test]
    fn colours_stay_in_range() {
        for _ in 0..200 {
            let drawing = svg(key(), 16);
            let hue: u32 = drawing
                .split("hsl(")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .and_then(|h| h.parse().ok())
                .expect("a hue");
            assert!(hue < 360, "hue {hue} is off the wheel");
        }
    }
}
