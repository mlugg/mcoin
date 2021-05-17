const std = @import("std");
const ed25519 = std.crypto.sign.Ed25519;
const sha256 = std.crypto.hash.sha2.Sha256;

const Transaction = struct {
    id: u64,
    quantity: u64,
    src_balance: u64,
    dst_balance: u64,
    src: [ed25519.public_length]u8,
    dst: [ed25519.public_length]u8,
    signature: ?[ed25519.signature_length]u8,

    pub fn serialLen(include_signature: bool) usize {
        var len = 4 * 8 + 2 * ed25519.public_length;
        if (include_signature) len += ed25519.signature_length;
        return len;
    }

    pub fn serialize(self: Transaction, include_signature: bool, w: std.io.Writer) !void {
        try w.writeIntLittle(self.id);
        try w.writeIntLittle(self.quantity);
        try w.writeAll(self.src);
        try w.writeAll(self.dst);
        if (include_signature) {
            if (self.signature) |signature| try w.writeAll(signature);
        }
    }

    pub fn sign(self: Transaction, keypair: ed25519.KeyPair) !void {
        if (keypair.public_key != src) {
            return error.KeyMismatch;
        }
        var buf: [Transaction.serialLen(false)]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        self.serialize(false, stream.writer()) catch unreachable;
        self.signature = try ed25519.sign(buf, keypair, null);
    }
};

const Block = struct {
    transactions: std.ArrayList(Transaction),
    prev_digest: [sha256.digest_length]u8,
    magic: u64,

    transactions_digest: [sha256.digest_length]u8,

    parent: ?*Block,
    children: std.ArrayList(*Block),

    pub fn addTransaction(self: Block, new_transaction: Transaction) void {
        self.transactions.append(new_transaction);

        var sha_ctx = sha256.init(.{});

        for (self.transactions) |t| {
            var buf: [Transaction.serialLen(true)]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buf);
            t.serialize(true, stream.writer()) catch unreachable;
            sha_ctx.update(buf);
        }

        sha_ctx.final(&self.transactions_digest);
    }

    pub fn calcDigest(self: Block) [sha256.digest_length]u8 {
        var buf: [2 * sha256.digest_length + 8]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        const w = stream.writer();
        w.writeAll(self.prev_digest) catch unreachable;
        w.writeAll(self.transactions_digest) catch unreachable;
        w.writeIntLittle(self.magic) catch unreachable;
        var digest: [sha256.digest_length]u8 = undefined;
        sha256.hash(buf, &digest, .{});
        return digest;
    }

    pub fn addToChain(trusted: Block) void {}
};

pub fn main() !void {
    std.log.info("All your codebase are belong to us.", .{});
}
