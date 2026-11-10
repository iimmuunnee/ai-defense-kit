<?php
function handle($request) {
    check_signature($request->getContent(), $request->header('TossPayments-Webhook-Signature'));
    if ($request->input('eventType') === 'PAYMENT_STATUS_CHANGED') { mark_paid(); }
}
