import json

from guardian.integrations.jira import adf


def test_round_trip_text_extraction():
    document = adf.doc(
        adf.heading("Title"),
        adf.paragraph("line one\nline two"),
        adf.labelled("Component", adf.code("lodash@4.17.20")),
        adf.bullet_list(["first", [adf.tag("verified"), " second"]]),
        adf.table(["A", "B"], [["1", adf.strong("2")]]),
        adf.code_block("/guardian accept\n/guardian revalidate"),
    )
    assert adf.adf_to_text(document) == (
        "Title\nline one\nline two\nComponent: lodash@4.17.20\nfirst\n[verified] second\n"
        "A\nB\n1\n2\n/guardian accept\n/guardian revalidate"
    )
    json.dumps(document)  # serialisable


def test_untrusted_text_stays_a_text_node():
    hostile = "[link|https://evil] *bold* <script>alert(1)</script> {{code}}\x00\x1b[31m"
    node = adf.paragraph(hostile)
    assert node["content"] == [
        {
            "type": "text",
            "text": "[link|https://evil] *bold* <script>alert(1)</script> {{code}}[31m",
        }
    ]


def test_empty_parts_are_valid_adf():
    assert adf.text("")["text"] == " "
    assert adf.bullet_list([]) is None
    assert adf.doc(None, adf.paragraph("x"))["content"] == [adf.paragraph("x")]
    assert adf.code_block("", "bash")["attrs"] == {"language": "bash"}
    assert adf.heading("h", 9)["attrs"]["level"] == 6


def test_long_text_is_truncated():
    assert len(adf.text("x" * 10_000)["text"]) == adf.MAX_TEXT_NODE_CHARS


def test_comment_shapes():
    comment = {
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "mention", "attrs": {"id": "1", "text": "@Alice"}},
                    {"type": "text", "text": " /guardian accept"},
                    {"type": "hardBreak"},
                    {"type": "emoji", "attrs": {"shortName": ":ok:"}},
                    {"type": "inlineCard", "attrs": {"url": "https://x"}},
                    {"type": "mystery", "content": [{"type": "text", "text": " inner"}]},
                    {"type": "text", "text": 5},
                    "stray string",
                    None,
                ],
            },
            {"type": "codeBlock", "content": [{"type": "text", "text": "code"}]},
        ],
    }
    assert adf.adf_to_text(comment) == "@Alice /guardian accept\n:ok:https://x inner\ncode"


def test_plain_strings_and_garbage():
    assert adf.adf_to_text("/guardian accept\x00") == "/guardian accept"
    assert adf.adf_to_text(None) == ""
    assert adf.adf_to_text(42) == ""
    assert adf.adf_to_text({"type": "doc", "content": "nope"}) == ""


def test_hostile_depth_and_size_are_bounded():
    node: dict = {"type": "text", "text": "deep"}
    for _ in range(10_000):
        node = {"type": "paragraph", "content": [node]}
    assert adf.adf_to_text(node) == ""  # beyond MAX_DEPTH, no RecursionError

    wide = {"type": "doc", "content": [{"type": "text", "text": "x" * 1000}] * 100_000}
    assert len(adf.adf_to_text(wide)) <= adf.MAX_OUTPUT_CHARS
