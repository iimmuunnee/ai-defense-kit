<?php
function handle($request) {
    check_signature($request->getContent(), $request->header('tosspayments-webhook-signature'));
    if ($request->input('eventType') === 'PAYMENT_STATUS_CHANGED') { mark_paid(); }
}
