(function() {var implementors = {};
implementors["chrono"] = [{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"chrono/naive/struct.NaiveDate.html\" title=\"struct chrono::naive::NaiveDate\">NaiveDate</a>",synthetic:false,types:["chrono::naive::date::NaiveDate"]},{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"chrono/naive/struct.NaiveTime.html\" title=\"struct chrono::naive::NaiveTime\">NaiveTime</a>",synthetic:false,types:["chrono::naive::time::NaiveTime"]},{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"chrono/naive/struct.NaiveDateTime.html\" title=\"struct chrono::naive::NaiveDateTime\">NaiveDateTime</a>",synthetic:false,types:["chrono::naive::datetime::NaiveDateTime"]},{text:"impl&lt;Tz:&nbsp;<a class=\"trait\" href=\"chrono/offset/trait.TimeZone.html\" title=\"trait chrono::offset::TimeZone\">TimeZone</a>&gt; <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"chrono/struct.DateTime.html\" title=\"struct chrono::DateTime\">DateTime</a>&lt;Tz&gt;",synthetic:false,types:["chrono::datetime::DateTime"]},{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"chrono/enum.Weekday.html\" title=\"enum chrono::Weekday\">Weekday</a>",synthetic:false,types:["chrono::Weekday"]},];
implementors["serde_json"] = [{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"serde_json/map/struct.Map.html\" title=\"struct serde_json::map::Map\">Map</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>, <a class=\"enum\" href=\"serde_json/value/enum.Value.html\" title=\"enum serde_json::value::Value\">Value</a>&gt;",synthetic:false,types:["serde_json::map::Map"]},{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"serde_json/value/enum.Value.html\" title=\"enum serde_json::value::Value\">Value</a>",synthetic:false,types:["serde_json::value::Value"]},{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"serde_json/struct.Number.html\" title=\"struct serde_json::Number\">Number</a>",synthetic:false,types:["serde_json::number::Number"]},];
implementors["super_analyzer_core"] = [{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"super_analyzer_core/criticality/enum.Criticality.html\" title=\"enum super_analyzer_core::criticality::Criticality\">Criticality</a>",synthetic:false,types:["super_analyzer_core::criticality::Criticality"]},{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"super_analyzer_core/results/utils/struct.Vulnerability.html\" title=\"struct super_analyzer_core::results::utils::Vulnerability\">Vulnerability</a>",synthetic:false,types:["super_analyzer_core::results::utils::Vulnerability"]},{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"super_analyzer_core/results/utils/struct.FingerPrint.html\" title=\"struct super_analyzer_core::results::utils::FingerPrint\">FingerPrint</a>",synthetic:false,types:["super_analyzer_core::results::utils::FingerPrint"]},{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"super_analyzer_core/results/struct.Results.html\" title=\"struct super_analyzer_core::results::Results\">Results</a>",synthetic:false,types:["super_analyzer_core::results::Results"]},];
implementors["toml"] = [{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"enum\" href=\"toml/value/enum.Value.html\" title=\"enum toml::value::Value\">Value</a>",synthetic:false,types:["toml::value::Value"]},{text:"impl <a class=\"trait\" href=\"serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"toml/value/struct.Datetime.html\" title=\"struct toml::value::Datetime\">Datetime</a>",synthetic:false,types:["toml::datetime::Datetime"]},];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()