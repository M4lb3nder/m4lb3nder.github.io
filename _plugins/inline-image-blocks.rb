#!/usr/bin/env ruby
# frozen_string_literal: true

require "cgi"

# Converts Markdown body blocks like:
# image:
#   path: /assets/img/example.webp
#   alt: Example image
#   caption: Optional caption
#
# into:
# <figure>
#   <img src="..." alt="...">
#   <figcaption>...</figcaption>
# </figure>
Jekyll::Hooks.register :posts, :pre_render do |post|
  content = post.content

  pattern = /
    ^image:\s*\n
    ^\s{2}path:\s*(?<path>.+?)\s*\n
    ^\s{2}alt:\s*(?<alt>.+?)\s*
    (?:\n^\s{2}caption:\s*(?<caption>.+?)\s*)?
    (?=\n{2,}|\z)
  /mx

  post.content = content.gsub(pattern) do
    raw_path = Regexp.last_match[:path].to_s.strip
    raw_alt = Regexp.last_match[:alt].to_s.strip
    raw_caption = Regexp.last_match[:caption].to_s.strip

    path = CGI.escapeHTML(raw_path)
    alt = CGI.escapeHTML(raw_alt)
    caption = CGI.escapeHTML(raw_caption.empty? ? raw_alt : raw_caption)

    <<~HTML.chomp
      <figure>
        <img src="#{path}" alt="#{alt}">
        <figcaption>#{caption}</figcaption>
      </figure>
    HTML
  end
end

