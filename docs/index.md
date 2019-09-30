## So, you wanna build a class-dump in 2019?

Building out an introspection tool for Apple platforms has changed considerably since the original [class-dump](http://stevenygard.com/projects/class-dump/) came out. Learning these new technologies can be qutie intimidating for the uninitiated. 

These articles aim to explain the complete process of programmatically inspecting a [Mach-O](https://en.wikipedia.org/wiki/Mach-O) (Apple) binary by systematically going throug the following:

* Apple's [Mach-O File Format](https://en.wikipedia.org/wiki/Mach-O)
* The symbol table (`<mach-o/nlist.h>`)
* dyld opcodes and binding
* Objective-C layout
* Swift layout
* ARM64e disk pointers

<!-- 
You can use the [editor on GitHub](https://github.com/DerekSelander/dsdump/edit/master/docs/index.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Markdown

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/DerekSelander/dsdump/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
 -->