const std = @import("std");

pub fn LinkedList(comptime T: type) type {
    return struct {
        head: ?*Node,
        tail: ?*Node,
        mutex: std.Thread.Mutex,
        size: u32,

        pub const Node = struct {
            value: T,
            prev: ?*Node = null,
            next: ?*Node = null,
        };

        const Self = @This();

        pub fn init() Self {
            return .{
                .head = null,
                .tail = null,
                .mutex = .{},
                .size = 0,
            };
        }

        /// Add a node to tha head
        pub fn add(self: *Self, node: *Node) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.head) |head| {
                node.next = head;
                head.prev = node;
                self.head = node;
                self.size += 1;
                return;
            }
            self.head = node;
            self.tail = node;
            self.size += 1;
        }

        /// Remove a node from the tail
        pub fn del(self: *Self) ?*Node {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.tail) |tail| {
                if (tail.prev) |tail_prev| {
                    self.tail = tail_prev;
                } else {
                    // tail has not prev, head = tails
                    self.tail = null;
                    self.head = null;
                }

                tail.prev = null;
                tail.next = null;
                self.size -= 1;
                return tail;
            }
            // no tail
            return null;
        }

        /// Promote a node to be the head
        pub fn promote(self: *Self, node: *Node) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.head == null) {
                unreachable;
            }

            // prev is null only for head
            if (node.prev) |prev| {
                prev.next = node.next;

                if (node == self.tail) {
                    self.tail = prev;
                } else {
                    node.next.?.prev = prev;
                }

                node.next = self.head;
                node.prev = null;

                self.head.?.prev = node;
                self.head = node;
                return;
            } else {
                // prev is null only for head
                return;
            }
            unreachable;
        }
    };
}

pub const expect = std.testing.expect;
pub const expectEqual = std.testing.expectEqual;

test "linked list, add delete 3" {
    const Item = struct { v: i32 };
    const ItemList = LinkedList(Item);

    var list = ItemList.init();
    var item = ItemList.Node{ .value = .{ .v = 1 } };
    list.add(&item);
    try expectEqual(1, list.size);
    try expectEqual(list.head, &item);
    try expectEqual(list.tail, &item);

    var item2 = ItemList.Node{ .value = .{ .v = 2 } };
    list.add(&item2);
    try expectEqual(2, list.size);
    try expectEqual(list.head, &item2);
    try expectEqual(list.tail, &item);
    try expectEqual(list.tail.?.prev, &item2);

    var item3 = ItemList.Node{ .value = .{ .v = 3 } };
    list.add(&item3);
    try expectEqual(3, list.size);
    try expectEqual(list.head, &item3);
    try expectEqual(list.tail, &item);

    _ = list.del();
    try expectEqual(2, list.size);
    try expectEqual(list.head, &item3);
    try expectEqual(list.tail, &item2);

    _ = list.del();
    try expectEqual(1, list.size);
    try expectEqual(list.head, &item3);
    try expectEqual(list.tail, &item3);

    _ = list.del();
    try expectEqual(0, list.size);
    try expectEqual(list.head, null);
    try expectEqual(list.tail, null);
}

test "promote tail, 3 items in the list" {
    const Item = struct { v: i32 };
    const ItemList = LinkedList(Item);

    var list = ItemList.init();
    var item = ItemList.Node{ .value = .{ .v = 1 } };
    list.add(&item);
    try expectEqual(1, list.size);
    try expectEqual(list.head, &item);
    try expectEqual(list.tail, &item);

    var item2 = ItemList.Node{ .value = .{ .v = 2 } };
    list.add(&item2);
    try expectEqual(2, list.size);
    try expectEqual(list.head, &item2);
    try expectEqual(list.tail, &item);
    try expectEqual(list.tail.?.prev, &item2);

    var item3 = ItemList.Node{ .value = .{ .v = 3 } };
    list.add(&item3);
    try expectEqual(3, list.size);
    try expectEqual(list.head, &item3);
    try expectEqual(list.tail, &item);

    // promote head
    list.promote(&item3);
    try expectEqual(3, list.size);
    try expectEqual(list.head, &item3);
    try expectEqual(list.tail, &item);

    // promote tail
    list.promote(&item);
    try expectEqual(3, list.size);
    try expectEqual(list.head, &item);
    try expectEqual(list.tail, &item2);

    _ = list.del();
    try expectEqual(2, list.size);
    try expectEqual(list.head, &item);
    try expectEqual(list.tail, &item3);

    _ = list.del();
    try expectEqual(1, list.size);
    try expectEqual(list.head, &item);
    try expectEqual(list.tail, &item);

    _ = list.del();
    try expectEqual(0, list.size);
    try expectEqual(list.head, null);
    try expectEqual(list.tail, null);
}

test "promote middle, 3 items in the list" {
    const Item = struct { v: i32 };
    const ItemList = LinkedList(Item);

    var list = ItemList.init();
    var item = ItemList.Node{ .value = .{ .v = 1 } };
    list.add(&item);
    try expectEqual(1, list.size);
    try expectEqual(list.head, &item);
    try expectEqual(list.tail, &item);

    var item2 = ItemList.Node{ .value = .{ .v = 2 } };
    list.add(&item2);
    try expectEqual(2, list.size);
    try expectEqual(list.head, &item2);
    try expectEqual(list.tail, &item);
    try expectEqual(list.tail.?.prev, &item2);

    var item3 = ItemList.Node{ .value = .{ .v = 3 } };
    list.add(&item3);
    try expectEqual(3, list.size);
    try expectEqual(list.head, &item3);
    try expectEqual(list.tail, &item);

    // promote middle
    list.promote(&item2);
    try expectEqual(3, list.size);
    try expectEqual(list.head, &item2);
    try expectEqual(list.tail, &item);
    try expectEqual(item.prev, &item3);
    try expectEqual(item3.prev, &item2);

    _ = list.del();
    try expectEqual(2, list.size);
    try expectEqual(list.head, &item2);
    try expectEqual(list.tail, &item3);

    _ = list.del();
    try expectEqual(1, list.size);
    try expectEqual(list.head, &item2);
    try expectEqual(list.tail, &item2);

    _ = list.del();
    try expectEqual(0, list.size);
    try expectEqual(list.head, null);
    try expectEqual(list.tail, null);
}
