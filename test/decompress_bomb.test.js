"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");
const zlib = require("zlib");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Deterministic exploit coverage for every read/extract API named in the
// CVE-2026-39244 advisory (getData, getDataAsync, readFile, readFileAsync,
// readAsText, readAsTextAsync, test, extractEntryTo, extractAllTo,
// extractAllToAsync). RSS alone is not a reliable signal because a large
// zero-filled Buffer.alloc is backed by lazily committed pages, so the Buffer
// allocators are instrumented while the API runs: every requested size is
// recorded and any request above ALLOC_LIMIT is refused, so vulnerable code
// fails fast instead of actually committing gigabytes.
const ALLOC_LIMIT = 64 * 1024 * 1024;

function allocationsDuring(fn) {
    const names = ["alloc", "allocUnsafe", "allocUnsafeSlow"];
    const originals = {};
    const result = { largest: 0, error: null, value: undefined };
    names.forEach((name) => {
        const original = Buffer[name];
        originals[name] = original;
        Buffer[name] = function (size) {
            if (typeof size === "number" && size > result.largest) {
                result.largest = size;
            }
            if (typeof size === "number" && size > ALLOC_LIMIT) {
                throw new Error("allocation guard: refused Buffer." + name + "(" + size + ")");
            }
            return original.apply(Buffer, arguments);
        };
    });
    try {
        result.value = fn();
    } catch (err) {
        result.error = err;
    } finally {
        names.forEach((name) => {
            Buffer[name] = originals[name];
        });
    }
    return result;
}

describe("decompression bomb (declared size) - CVE-2026-39244 - read/extract API allocation bounds", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB
    const DECLARED_MAX32 = 0xfffffffe; // ~4 GB, the largest classic (non zip64 marker) size
    const destination = pth.join(os.tmpdir(), "adm-zip-cve-2026-39244-" + process.pid);

    const storedBomb = (declared) => craftBomb(declared, 0 /* STORED */, Buffer.from("A"));
    // a valid raw deflate stream (so inflation succeeds) that is only let down by its crc
    const deflatedBomb = (declared) => craftBomb(declared, 8 /* DEFLATED */, zlib.deflateRawSync(Buffer.from("A")));

    const expectBounded = (res) => {
        expect(res.largest, "largest Buffer allocation must be bound by real data, not the declared size").to.be.below(ALLOC_LIMIT);
    };
    const expectCrcError = (err) => {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.match(/CRC32/);
    };

    afterEach((done) => rimraf(destination, done));

    it("entry.getData() on a STORED entry declaring ~4 GB", () => {
        const entry = new Zip(storedBomb(DECLARED_MAX32)).getEntries()[0];
        const res = allocationsDuring(() => entry.getData());
        expectBounded(res);
        expectCrcError(res.error);
    });

    it("entry.getData() on a DEFLATED entry declaring ~3 GB", () => {
        const entry = new Zip(deflatedBomb(DECLARED)).getEntries()[0];
        const res = allocationsDuring(() => entry.getData());
        expectBounded(res);
        expectCrcError(res.error);
    });

    it("entry.getDataAsync() on a STORED entry", () => {
        const entry = new Zip(storedBomb(DECLARED)).getEntries()[0];
        const calls = [];
        const res = allocationsDuring(() => entry.getDataAsync((data, err) => calls.push({ data: data, err: err })));
        expectBounded(res);
        expect(calls).to.have.lengthOf(1);
        expect(calls[0].data.length).to.equal(1);
        expectCrcError(calls[0].err);
    });

    it("entry.getDataAsync() on a DEFLATED entry", (done) => {
        const entry = new Zip(deflatedBomb(DECLARED)).getEntries()[0];
        const res = allocationsDuring(() =>
            entry.getDataAsync((data, err) => {
                try {
                    expect(data.length).to.equal(1);
                    expectCrcError(err);
                    done();
                } catch (e) {
                    done(e);
                }
            })
        );
        expectBounded(res);
        expect(res.error).to.equal(null);
    });

    it("readFile() on STORED and DEFLATED entries", () => {
        [storedBomb(DECLARED), deflatedBomb(DECLARED)].forEach((archive) => {
            const zip = new Zip(archive);
            const res = allocationsDuring(() => zip.readFile("a"));
            expectBounded(res);
            expectCrcError(res.error);
        });
    });

    it("readFileAsync() on a DEFLATED entry", (done) => {
        const zip = new Zip(deflatedBomb(DECLARED));
        const res = allocationsDuring(() =>
            zip.readFileAsync("a", (data, err) => {
                try {
                    expect(data.length).to.equal(1);
                    expectCrcError(err);
                    done();
                } catch (e) {
                    done(e);
                }
            })
        );
        expectBounded(res);
        expect(res.error).to.equal(null);
    });

    it("readAsText() on STORED and DEFLATED entries", () => {
        [storedBomb(DECLARED), deflatedBomb(DECLARED)].forEach((archive) => {
            const zip = new Zip(archive);
            const res = allocationsDuring(() => zip.readAsText("a"));
            expectBounded(res);
            expectCrcError(res.error);
        });
    });

    it("readAsTextAsync() on a STORED entry", () => {
        const zip = new Zip(storedBomb(DECLARED));
        const calls = [];
        const res = allocationsDuring(() => zip.readAsTextAsync("a", (data, err) => calls.push({ data: data, err: err })));
        expectBounded(res);
        expect(calls).to.have.lengthOf(1);
        expectCrcError(calls[0].err);
    });

    it("test() on STORED and DEFLATED entries", () => {
        [storedBomb(DECLARED), deflatedBomb(DECLARED)].forEach((archive) => {
            const zip = new Zip(archive);
            const res = allocationsDuring(() => zip.test());
            expectBounded(res);
            expect(res.error).to.equal(null);
            expect(res.value).to.equal(false);
        });
    });

    it("extractEntryTo() on STORED and DEFLATED entries", () => {
        [storedBomb(DECLARED), deflatedBomb(DECLARED)].forEach((archive) => {
            const zip = new Zip(archive);
            const res = allocationsDuring(() => zip.extractEntryTo("a", destination, false, true));
            expectBounded(res);
            expectCrcError(res.error);
            expect(fs.existsSync(pth.join(destination, "a"))).to.equal(false);
        });
    });

    it("extractAllTo() on STORED and DEFLATED entries", () => {
        [storedBomb(DECLARED), deflatedBomb(DECLARED)].forEach((archive) => {
            const zip = new Zip(archive);
            const res = allocationsDuring(() => zip.extractAllTo(destination, true));
            expectBounded(res);
            expectCrcError(res.error);
            expect(fs.existsSync(pth.join(destination, "a"))).to.equal(false);
        });
    });

    it("extractAllToAsync() on a DEFLATED entry", () => {
        const zip = new Zip(deflatedBomb(DECLARED));
        const res = allocationsDuring(() => zip.extractAllToAsync(destination, true));
        expectBounded(res);
        expect(res.error).to.equal(null);
        return res.value.then(
            () => {
                throw new Error("extractAllToAsync must reject an entry with a bad crc");
            },
            (err) => {
                expectCrcError(err);
                expect(fs.existsSync(pth.join(destination, "a"))).to.equal(false);
            }
        );
    });

    it("still reads a genuinely STORED entry (sync and async)", (done) => {
        const payload = Buffer.from("stored payload ".repeat(100));
        const zip = new Zip();
        zip.addFile("s.bin", payload);
        zip.getEntry("s.bin").header.method = 0; // force STORED
        const round = new Zip(zip.toBuffer());
        const entry = round.getEntry("s.bin");
        expect(entry.header.method).to.equal(0);
        expect(round.readFile("s.bin").equals(payload)).to.equal(true);
        round.readFileAsync("s.bin", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a legitimate DEFLATED entry asynchronously", (done) => {
        const payload = Buffer.from("hello world ".repeat(5000));
        const zip = new Zip();
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.getEntry("d.txt").header.method).to.equal(8);
        round.readFileAsync("d.txt", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });
});
