import Foundation

@main
struct ChannelRemovalReceiptTests {
    static func expect(_ value: @autoclosure () -> Bool, _ message: String) {
        if !value() { fatalError(message) }
    }

    static func main() {
        let noFlows = ChannelDrainUpdate(remaining: 0, previouslyStarted: nil, closeFailed: false, now: 100)
        expect(noFlows.status == "revoked", "An omitted formerly-permitted family with no flows must not publish ok")
        expect(noFlows.closingSince == nil && noFlows.appliedAt == 100, "Confirmed closure records its actual application time")

        let closing = ChannelDrainUpdate(remaining: 2, previouslyStarted: nil, closeFailed: false, now: 101)
        expect(closing.status == "disconnecting", "Outstanding flows cannot be called revoked")
        expect(closing.closingSince == 101 && closing.appliedAt == 101, "First removal starts the drain deadline")
        let repeated = ChannelDrainUpdate(remaining: 1, previouslyStarted: closing.closingSince, closeFailed: false, now: 102)
        expect(repeated.status == "disconnecting" && repeated.closingSince == 101, "Another family's renewal cannot restart the drain timer")
        let timedOut = ChannelDrainUpdate(remaining: 1, previouslyStarted: repeated.closingSince, closeFailed: false, now: 102.5)
        expect(timedOut.status == "failed" && timedOut.closingSince == 101, "Unconfirmed closure times out against the original removal")
        expect(timedOut.appliedAt == 102.5, "Timeout outcome uses the actual processing time")

        let failedClose = ChannelDrainUpdate(remaining: 1, previouslyStarted: nil, closeFailed: true, now: 110)
        expect(failedClose.status == "failed" && failedClose.closingSince == 110, "A known socket close failure is reported immediately")
        let retriedFailure = ChannelDrainUpdate(remaining: 1, previouslyStarted: failedClose.closingSince, closeFailed: true, now: 110.2)
        expect(retriedFailure.status == "failed" && retriedFailure.closingSince == 110, "A repeated failed close cannot downgrade to disconnecting")
        let confirmed = ChannelDrainUpdate(remaining: 0, previouslyStarted: timedOut.closingSince, closeFailed: false, now: 112)
        expect(confirmed.status == "revoked" && confirmed.closingSince == nil && confirmed.appliedAt == 112,
            "A failed/timed-out drain can become revoked only after actual closure")

        // Each family supplies its own start time; none of these transitions can
        // change the continuing family's permit or its unrelated drain deadline.
        let otherFamily = ChannelDrainUpdate(remaining: 1, previouslyStarted: 109, closeFailed: false, now: 110)
        expect(otherFamily.status == "disconnecting" && otherFamily.closingSince == 109, "Family drain deadlines are independent")
        print("PASS: removed-family receipts, first drain deadline, close failures, completion timestamps, and family independence")
    }
}
