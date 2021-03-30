# Input format

The calculator input format may look a bit strange, so to simplify it we use the following conventions:

* anything in `[`,`]` - exact button to press, the exact thing written on it, for example:
    * `[CALC]`
    * `[SHIFT]`
    * `[ALPHA]`

* anything starting with either `csxx` or `CONSTxx` - a constant from the constant table at position `xx`

* anything starting with either `cvxx` or `CONVxx` - a convertion from the conversion table at position `xx`

* Anything else is the exact character that should be seen on screen (when in LineIO)
