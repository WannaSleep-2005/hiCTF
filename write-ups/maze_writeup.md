# Warden's Maze — Challenge Write-up

## Summary

The goal is to reach the prize (`$`) inside the sealed central vault. Ordinary movement blocks the vault tiles (`%`), but the visibility renderer contains an indexing bug that can replace one vault wall tile with a floor tile. Once the wall is overwritten, the player can enter and collect the prize.

**Win token:** `hiCTF{maze-warden-vault-seed-2026_2c86d3311e}`

## Reverse engineering

The binary is a stripped x86-64 Linux ELF. The maze is stored as a row-major grid with 24 columns. The renderer traces visibility rays from the player's position and marks cells as explored.

For a ray endpoint, the expected linear map index is:

```text
index = player_row * 24 + player_col + row_delta * 24 + col_delta
```

The renderer also makes a hand-rolled update using an 8-bit signed offset. In the useful case, the ray endpoint is six rows below the player and has no column offset:

```text
row_delta * width = 6 * 24 = 144
(int8_t)144 = -112
```

This means the renderer reads the tile at the correct endpoint but writes its tile value to a different index, 256 cells earlier in the linear grid. The write keeps the tile's low bits and sets its explored bit, so an open endpoint can overwrite a wall as floor.

## Triggering the overwrite

At row 14, column 4, the visibility ray reaches the open cell at row 20, column 4. The intended endpoint index is:

```text
20 * 24 + 4 = 484
```

Because of the signed-byte truncation, the renderer instead writes to:

```text
14 * 24 + 4 - 112 = 228 = 9 * 24 + 12
```

That target is the `%` wall at row 9, column 12, on the vault's upper edge. The renderer changes it to floor. Walking through that opening and stepping onto `$` wins the game.

## Move sequence

Starting from the initial position, send these moves, each followed by Enter:

```text
daaaaasssaasssdsssdsssaaasaddddwwwawwwdddddsssa
```

The sequence first reaches the position that triggers the bad visibility write, then routes through the opened vault wall to the prize.

## Result

On entering the prize tile, the service printed:

```text
hiCTF{maze-warden-vault-seed-2026_2c86d3311e}
```
